// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// geth is the official command-line client for Ethereum.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/cmd/utils"
	"github.com/usechain/go-usechain/common"
	//"github.com/usechain/go-usechain/commitee/committee"
	"github.com/usechain/go-usechain/console"
	"github.com/usechain/go-usechain/contracts/authentication"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/eth"
	"github.com/usechain/go-usechain/ethclient"
	//"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/commitee/committee"
	"github.com/usechain/go-usechain/internal/debug"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/metrics"
	"github.com/usechain/go-usechain/node"
	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "used" // Client identifier to advertise over the network

	normalRole    = 0
	committeeRole = 1
	verifierRole  = 2
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	// Ethereum address of the Geth release oracle.
	relOracle = common.HexToAddress("0xfa7b9770ca4cb04296cac84f37736d4041251cdf")
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, "the go-usechain command line interface")
	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.VerifyIdFlag,
		utils.VerifyPhotoFlag,
		utils.VerifyQueryFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.NoUSBFlag,
		utils.DashboardEnabledFlag,
		utils.DashboardAddrFlag,
		utils.DashboardPortFlag,
		utils.DashboardRefreshFlag,
		utils.DashboardAssetsFlag,
		utils.EthashCacheDirFlag,
		utils.EthashCachesInMemoryFlag,
		utils.EthashCachesOnDiskFlag,
		utils.EthashDatasetDirFlag,
		utils.EthashDatasetsInMemoryFlag,
		utils.EthashDatasetsOnDiskFlag,
		utils.TxPoolNoLocalsFlag,
		utils.TxPoolJournalFlag,
		utils.TxPoolRejournalFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.FastSyncFlag,
		utils.LightModeFlag,
		utils.SyncModeFlag,
		utils.GCModeFlag,
		utils.LightServFlag,
		utils.LightPeersFlag,
		utils.LightKDFFlag,
		utils.CacheFlag,
		utils.CacheDatabaseFlag,
		utils.CacheGCFlag,
		utils.TrieCacheGenFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.UsebaseFlag,
		utils.GasPriceFlag,
		utils.CommitteeEnabledFlag,
		utils.MinerThreadsFlag,
		utils.MiningEnabledFlag,
		utils.TargetGasLimitFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.TestnetFlag,
		utils.MoonetFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.RPCVirtualHostsFlag,
		utils.EthStatsURLFlag,
		utils.MetricsEnabledFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.ExtraDataFlag,
		configFileFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
	}

	whisperFlags = []cli.Flag{
		utils.WhisperEnabledFlag,
		utils.WhisperMaxMessageSizeFlag,
		utils.WhisperMinPOWFlag,
	}
)

func init() {
	// Initialize the CLI app and start Geth
	app.Action = geth
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2017-2018 The go-usechain Authors"
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		copydbCommand,
		removedbCommand,
		dumpCommand,
		// See monitorcmd.go:
		monitorCommand,
		// See accountcmd.go:
		accountCommand,
		verifyCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		makecacheCommand,
		makedagCommand,
		versionCommand,
		bugCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)
	app.Flags = append(app.Flags, whisperFlags...)

	app.Before = func(ctx *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		// Start system runtime metrics collection
		go metrics.CollectProcessMetrics(3 * time.Second)

		utils.SetupNetwork(ctx)
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// geth is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func geth(ctx *cli.Context) error {
	node := makeFullNode(ctx)
	startNode(ctx, node)
	node.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node) {
	// Start up the node itself
	utils.StartNode(stack)

	// Unlock any account specifically requested
	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	passwords := utils.MakePasswordList(ctx)
	unlocks := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for i, account := range unlocks {
		if trimmed := strings.TrimSpace(account); trimmed != "" {
			unlockAccount(ctx, ks, trimmed, i, passwords)
		}
	}
	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	go func() {
		// Create an chain state reader for self-derivation
		rpcClient, err := stack.Attach()
		if err != nil {
			utils.Fatalf("Failed to attach to self: %v", err)
		}
		stateReader := ethclient.NewClient(rpcClient)

		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				if event.Wallet.URL().Scheme == "ledger" {
					event.Wallet.SelfDerive(accounts.DefaultLedgerBaseDerivationPath, stateReader)
				} else {
					event.Wallet.SelfDerive(accounts.DefaultBaseDerivationPath, stateReader)
				}

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	var usechain *eth.Ethereum
	if err := stack.Service(&usechain); err != nil {
		utils.Fatalf("Usechain service not running: %v", err)
	}

	///TODO: committee config should read from contract, update it in next version
	commitFlag, ID, privShare, err := crypto.ParseCommitteeID()
	if err != nil || commitFlag == normalRole {
		log.Info("Normal node")
	} else {
		log.Info("Committee node", "ID", ID)
		log.Warn("As a committee, pls keep your account unlocked in 30 second")
	}

	///TODO:leave the space for committee, add shares storage in future
	go func() {
		cachedLastCertIDChecked := int64(0)
		time.Sleep(30 * time.Second)
		// Committing only makes sense if it is a committee
		for commitFlag == committeeRole {
			// statdb read
			// wait for some second to read data from stateDB
			time.Sleep(2 * time.Second)

			// contract address added
			ContractAddr := common.HexToAddress(common.AuthenticationContractAddressString)

			// read unConfirmedAddressLen from unconfirmed address list
			// generate key
			keyIndex, _ := authentication.ExpandToIndex(authentication.UnConfirmedAddressLen, "", 0)
			resultUnConfirmedAddressLen := usechain.TxPool().State().GetState(ContractAddr, common.HexToHash(keyIndex))
			unConfirmedAddressLen := authentication.GetLen(resultUnConfirmedAddressLen[:])
			if unConfirmedAddressLen == 0 {
				continue
			}
			// get unConfirmedAddress data
			for i := int64(0); i < unConfirmedAddressLen; i++ {
				res1, res2, res3, res4 := committee.ReadUnconfirmedAddress(usechain, i, ContractAddr, cachedLastCertIDChecked)

				if res4 == 0 {
					continue
				}
				log.Info("res1, res2, res3", "res1", res1, "res2", res2, "res3", res3)
				log.Info("unConfirmedAddressLen: ", "len", unConfirmedAddressLen)
				cachedLastCertIDChecked = res4

				certID := res1[22:]
				ringSig := res2
				A1S1 := res3

				err, pubSet, _, _, _ := crypto.DecodeRingSignOut(ringSig)
				if err != nil {
					log.Error("RingSig decode failed!", err)
				}

				shareStrSet := committee.GeneratePubShare(pubSet, privShare)
				log.Info("A1, S1, pubSet", "A1S1", A1S1, "shareStrSet", shareStrSet)
				ID := "00000000000000000000000000000000000000000001"

				log.Info("The sending msg:", "info", A1S1+certID+ID+shareStrSet)

				committee.SendCommitteeMsg(usechain, A1S1+certID+ID+shareStrSet)
			}
		}
	}()

	///TODO:leave the space for verifier, add shares storage in future
	go func() {
		time.Sleep(30 * time.Second)
		// Committing only makes sense if it is
		for commitFlag == verifierRole {
			time.Sleep(time.Second * 1)
			if true {
				///TODO: GetTheLastInternalTrans Optimization
				addr, msg := core.GetTheLastInternalTrans()
				if msg == nil {
					continue
				}
				log.Info("The sender is: ", "sender", addr)

				//committee scan
				A1S1, certID, senderId, shares, err := committee.ExtractPubShareMsg(string(msg))
				if err != nil {
					log.Error("The pub share msg extract failed", err)
					break
				}
				log.Info("Result is:", A1S1, certID, senderId, shares)

				//insert in local map, first check whether existed already
				if !committee.InStringArraySet(A1S1, senderId) {
					committee.MsgMap[A1S1] = append(committee.MsgMap[A1S1], shares)
					committee.MsgCheckMap[A1S1] = append(committee.MsgCheckMap[A1S1], 1)

					if len(committee.MsgMap[A1S1]) >= 2 {
						//if scan the map and get a matched account，
						//send a confirm tx to contract to change the account verify stat
						if committee.CheckGetValidA1S1(A1S1) {
							committee.SendAccountConfirmMsg(usechain, certID, 1)
						}
					}
				}
			}
		}
	}()

	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
		// Mining only makes sense if a fuexitll Ethereum node is running
		if ctx.GlobalBool(utils.LightModeFlag.Name) || ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
			utils.Fatalf("Light clients do not support mining")
		}
		var ethereum *eth.Ethereum
		if err := stack.Service(&ethereum); err != nil {
			utils.Fatalf("Ethereum service not running: %v", err)
		}
		// Use a reduced number of threads if requested
		if threads := ctx.GlobalInt(utils.MinerThreadsFlag.Name); threads > 0 {
			type threaded interface {
				SetThreads(threads int)
			}
			if th, ok := ethereum.Engine().(threaded); ok {
				th.SetThreads(threads)
			}
		}
		// Set the gas price to the limits from the CLI and start mining
		ethereum.TxPool().SetGasPrice(utils.GlobalBig(ctx, utils.GasPriceFlag.Name))
		if err := ethereum.StartMining(true); err != nil {
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}
