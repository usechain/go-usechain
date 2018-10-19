.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/usechain/go-usechain/cmd/swarm
	go build -o bin/used     github.com/usechain/go-usechain/cmd/used
	go build -o bin/bootnode github.com/usechain/go-usechain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/usechain/go-usechain/swarm/...
