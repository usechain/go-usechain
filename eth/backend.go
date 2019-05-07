// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"errors"
	"fmt"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/consensus"
	"github.com/usechain/go-usechain/consensus/clique"
	"github.com/usechain/go-usechain/consensus/rpow"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/core/bloombits"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/core/vm"
	"github.com/usechain/go-usechain/eth/downloader"
	"github.com/usechain/go-usechain/eth/filters"
	"github.com/usechain/go-usechain/eth/gasprice"
	"github.com/usechain/go-usechain/ethdb"
	"github.com/usechain/go-usechain/event"
	"github.com/usechain/go-usechain/internal/ethapi"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/miner"
	"github.com/usechain/go-usechain/node"
	"github.com/usechain/go-usechain/p2p"
	"github.com/usechain/go-usechain/params"
	"github.com/usechain/go-usechain/rlp"
	"github.com/usechain/go-usechain/rpc"
	"github.com/usechain/go-usechain/vote"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
}

// Usechain implements the Usechain full node service.
type Ethereum struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan  chan bool    // Channel for shutting down the ethereum
	stopDbUpgrade func() error // stop chain db sequential key upgrade

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	ApiBackend *EthApiBackend

	miner    *miner.Miner
	gasPrice *big.Int
	usebase  common.Address

	voter *vote.Voter

	networkId     uint64
	netRPCService *ethapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and usebase)
}

func (s *Ethereum) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// New creates a new Usechain object (including the
// initialisation of the common Usechain object)
func New(ctx *node.ServiceContext, config *Config) (*Ethereum, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}
	stopDbUpgrade := upgradeDeduplicateData(chainDb)
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	//log.Info("Initialised chain configuration", "config", chainConfig)

	eth := &Ethereum{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, &config.Rpow, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		stopDbUpgrade:  stopDbUpgrade,
		networkId:      config.NetworkId,
		gasPrice:       config.GasPrice,
		usebase:        config.Usebase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
	}

	log.Info("Initialising usechain protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := core.GetBlockChainVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run use upgradedb.\n", bcVersion, core.BlockChainVersion)
		}
		core.WriteBlockChainVersion(chainDb, core.BlockChainVersion)
	}
	var (
		vmConfig    = vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
		cacheConfig = &core.CacheConfig{Disabled: config.NoPruning, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
	)
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, eth.chainConfig, eth.engine, vmConfig)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		core.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, eth.chainConfig, eth.blockchain, ctx.AccountManager)

	if eth.protocolManager, err = NewProtocolManager(eth.chainConfig, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb, eth.txPool.StateDB()); err != nil {
		return nil, err
	}
	eth.miner = miner.New(eth, eth.chainConfig, eth.EventMux(), eth.engine)
	eth.miner.SetExtra(makeExtraData(config.ExtraData))

	//add voter
	eth.voter = vote.NewVoter(eth, eth.usebase)

	eth.ApiBackend = &EthApiBackend{eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	eth.ApiBackend.gpo = gasprice.NewOracle(eth.ApiBackend, gpoParams)

	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"used",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (ethdb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*ethdb.LDBDatabase); ok {
		db.Meter("eth/db/chaindata/")
	}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service
func CreateConsensusEngine(ctx *node.ServiceContext, config *rpow.Config, chainConfig *params.ChainConfig, db ethdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}
	// Otherwise assume random-proof-of-work
	switch {
	case config.RpowMode == rpow.ModeFake:
		log.Warn("Rpow used in fake mode")
		return rpow.NewFaker()
	case config.RpowMode == rpow.ModeTest:
		log.Warn("Rpow used in test mode")
		return rpow.NewTester()
	default:
		engine := rpow.NewFaker()
		engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs returns the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.ApiBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, false),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "voter",
			Version:   "1.0",
			Service:   NewPrivateVoterAPI(s),
			Public:    false,
		}, {
			Namespace: "use",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "use",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "use",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "use",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Usebase() (eb common.Address, err error) {
	s.lock.RLock()
	usebase := s.usebase
	s.lock.RUnlock()

	if usebase != (common.Address{}) {
		return usebase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			usebase := accounts[0].Address

			s.lock.Lock()
			s.usebase = usebase
			s.lock.Unlock()

			log.Info("Usebase automatically configured", "address", usebase)
			return usebase, nil
		}
	}
	return common.Address{}, fmt.Errorf("usebase must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (self *Ethereum) SetUsebase(usebase common.Address) {
	self.lock.Lock()
	self.usebase = usebase
	self.lock.Unlock()

	self.miner.SetUsebase(usebase)
}

func (s *Ethereum) StartMining(local bool) error {
	eb, err := s.Usebase()
	if err != nil {
		log.Error("Cannot start mining without usebase", "err", err)
		return fmt.Errorf("usebase missing: %v", err)
	}
	var wallet accounts.Wallet
	if clique, ok := s.engine.(*clique.Clique); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Usebase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		clique.Authorize(eb, wallet.SignHash)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so noone will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
	}

	//Sign the miner on line tx, and broadcast it
	wallet, err = s.accountManager.Find(accounts.Account{Address: eb})
	if wallet == nil || err != nil {
		log.Error("Usebase account unavailable locally", "err", err)
		return fmt.Errorf("signer missing: %v", err)
	}

	if !sendMinerOnLine(s.txPool, eb, wallet) {
		log.Error("Miner start failed, Please try miner.start() again")
		return nil
	}

	go s.miner.Start(eb)
	return nil
}

func sendMinerOnLine(pool *core.TxPool, eb common.Address, wallet accounts.Wallet) bool {
	//new a transaction
	addr := common.HexToAddress("0xfffffffffffffffffffffffffffffffff0000002")
	nonce := pool.State().GetNonce(eb)
	data, _ := hexutil.Decode("0xb1d80a7b")
	args := ethapi.SendTxArgs{}
	args.Flag = new(hexutil.Uint8)
	args.Nonce = (*hexutil.Uint64)(&nonce)
	args.From = eb
	args.To = &addr

	tx := types.NewTransaction(uint64(*args.Nonce), *args.To, nil, 2000000, big.NewInt(20000000000), data)

	signedTx, err := wallet.SignTx(accounts.Account{Address: eb}, tx, nil)
	if err != nil {
		log.Error("Sign the miner on line Msg failed, Please unlock the verifier account", "err", err)
		return false
	}

	log.Info("Miner on line Msg is sent", "hash", signedTx.Hash().String())
	//add tx to the txpool
	err = pool.AddLocal(signedTx)
	if err != nil {
		log.Warn("Miner on line Msg sent failed", "err", err)
		return false
	}
	return true
}

//Get the vote base
func (s *Ethereum) Votebase() (eb common.Address, err error) {
	s.lock.RLock()
	votebase := s.voter.Votebase()
	s.lock.RUnlock()

	if votebase != (common.Address{}) {
		return votebase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			votebase := accounts[0].Address
			return votebase, nil
		}
	}
	return common.Address{}, fmt.Errorf("votebase must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (self *Ethereum) SetVotebase(votebase common.Address) {
	self.voter.SetVotebase(votebase)
}

// Start Voting via admin interface or wrapper from cli flags
func (s *Ethereum) StartVoting() error {
	vb, err := s.Votebase()
	if err != nil {
		log.Error("Cannot start mining without votebase", "err", err)
		return fmt.Errorf("votebase missing: %v", err)
	}
	go s.voter.Start(vb)
	return nil
}

func (s *Ethereum) StopMining() {
	if !s.IsMining() {
		s.miner.Stop()
		return
	}
	eb, err := s.Usebase()
	if err != nil {
		log.Error("Cannot stop mining without usebase", "err", err)
		return
	}
	var wallet accounts.Wallet
	if clique, ok := s.engine.(*clique.Clique); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Usebase account unavailable locally", "err", err)
			return
		}
		clique.Authorize(eb, wallet.SignHash)
	}

	//Sign the miner off line tx, and broadcast it
	wallet, err = s.accountManager.Find(accounts.Account{Address: eb})
	if !sendMinerOffLine(s.txPool, eb, wallet) {
		fmt.Println("Miner stop failed, Please try miner.stop() again")
		return
	}
	s.miner.Stop()
}

func sendMinerOffLine(pool *core.TxPool, eb common.Address, wallet accounts.Wallet) bool {
	//new a transaction
	addr := common.HexToAddress("0xfffffffffffffffffffffffffffffffff0000002")
	nonce := pool.StateDB().GetNonce(eb)
	data, _ := hexutil.Decode("0x92915992")
	args := ethapi.SendTxArgs{}
	args.Flag = new(hexutil.Uint8)
	args.Nonce = (*hexutil.Uint64)(&nonce)
	args.From = eb
	args.To = &addr

	tx := types.NewTransaction(uint64(*args.Nonce), *args.To, nil, 2000000, big.NewInt(20000000000), data)

	signedTx, err := wallet.SignTx(accounts.Account{Address: eb}, tx, nil)
	if err != nil {
		log.Error("Sign the miner off line Msg failed, Please unlock the verifier account", "err", err)
		return false
	}

	log.Info("Miner off line Msg is sent", "hash", signedTx.Hash().String())
	//add tx to the txpool
	err = pool.AddLocal(signedTx)
	if err != nil {
		log.Warn("Miner off line Msg sent failed", "err", err)
		return false
	}
	return true
}

func (s *Ethereum) IsMining() bool      { return s.miner.Mining() }
func (s *Ethereum) Miner() *miner.Miner { return s.miner }

func (s *Ethereum) StopVoting()    { s.voter.Stop() }
func (s *Ethereum) IsVoting() bool { return s.voter.Voting() }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) ChainID() *big.Int                  { return s.chainConfig.ChainId }
func (s *Ethereum) TxPool() *core.TxPool               { return s.txPool }
func (s *Ethereum) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *Ethereum) NetVersion() uint64                 { return s.networkId }
func (s *Ethereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	if s.stopDbUpgrade != nil {
		s.stopDbUpgrade()
	}
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
