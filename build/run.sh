#!/bin/bash
# run usechain deamon node
# zhouhh@usechain.net
# 2018.7.30

curdir=$(cd "$(dirname "$0")"; pwd)

# run light node and store data in ${HOME}/.usechain, not supported now 
# ${curdir}/bin/used --rpc --rpcaddr localhost --rpcport "8545" --syncmode "light" 

# run full mode
# ${curdir}/bin/used --rpc --rpcaddr localhost --rpcport "8545" 

# run test node, if set --datadir, you should uncomment the code below to make directory.
#if [ ! -d "${curdir}/bin/chaindata" ]; then
#    echo "mkdir ${curdir}/bin/chaindata"
#    mkdir ${curdir}/bin/chaindata
#fi

# the parameter --moonet is the same as --networkid "2"

# echo "${curdir}/bin/used --networkid "2"  --datadir ${curdir}/bin/chaindata --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "use,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' console"
# ${curdir}/bin/used --networkid "2"  --datadir ${curdir}/bin/chaindata --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "use,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' console 

echo "${curdir}/bin/used --moonet --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "use,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' console"
${curdir}/bin/used --moonet  --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "use,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' console 


# nohup ${curdir}/bin/used --networkid "2"  --datadir ${curdir}/bin/chaindata --ipcdisable --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "used,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' & 
# nohup ${curdir}/bin/used --networkid "2"  --datadir ${curdir}/bin/chaindata --rpc --rpcaddr=0.0.0.0 --rpcport "8545" --rpcapi "used,eth,db,net,web3,personal,admin,txpool,clique,miner" --rpccorsdomain '*' & 
