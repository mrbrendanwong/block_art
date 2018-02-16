#!/bin/sh
# Generate keys
go run ppkeygen.go
# Read files into env variables
PRIVKEY=`cat privkey`
PUBKEY=`cat pubkey`
# Grab server from command line
SERVER=$1
go run ink-miner.go $SERVER $PUBKEY $PRIVKEY