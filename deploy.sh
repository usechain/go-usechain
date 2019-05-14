#!/bin/bash

echo "deploy single node begin!"

make used

used="./build/bin/used"
datadir="./tests/functional/testdata"

if [ ! -f "$used" ]; then
    echo "make failed!"
    exit 1
fi

$used init ./build/config/genesisSingle.json --datadir ./tests/functional/testdata/

$used --datadir $datadir --ipcdisable --rpc --rpcaddr=0.0.0.0  --rpcapi "use,net,web3,personal,admin,txpool,cliqu,miner,eth,voter" --rpccorsdomain '*' --rpcport 8545 --port 30303 --networkid 3
