#!/bin/bash

# Generate public, private key files
go run ppkeygen.go

# Read files into env variables
PRIVKEY=`cat privkey`
PUBKEY=`cat pubkey`

# Grab server from command line
SERVER=$1

# Run ink-miner.go
go run ink-miner.go $SERVER $PUBKEY $PRIVKEY
