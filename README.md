# Overview

# Running This System
server.go: `server.go -c config.json`

ink-miner.go: `go run ink-miner.go [server ip:port] [pubKey] [privkey]`

ppkeygen.go: `go run ppkeygen.go`

startminer.sh: `go run startminer.sh [server ip:port]`

<INSERT INSTRUCTIONS FOR ART>

# System Design
## Miner
An ink miner mines for ink for an art application to use. 

The miner will first establish an ongoing RPC to the server it was initialized with. The miner will retrieve its local IP and make an RPC call to register its metadata to the server. If successful, the server will return the genesis block of the blockchain and various settings that the miner will adhere to when mining and interacting with its network. The server will then begin sending heartbeats to the server

While the miner is idle and is not receiving any instruction from art nodes, or it does not have enough miners in its network to begin mining Op blocks, it will mine for no-op blocks.

In a separate thread, the miner will monitor the number of other miners it is connected to. While it's under the miner threshold, it will make an RPC call to the server every few seconds to check for new connected miners. Whenever it sees a new miner, it will attempt to establish a two way RPC connection to it.

Within the main thread, the miner will continously listen for any RPC calls. 

## Server
A server will act as an address book for miners. It will keep track of the IPs and public keys of all miners that register to it. A miner will call the server every time it wants to come into contact with new miners.

## Art Node

## Block Art API

# Blockchain Design

## Block Generation

## Block Chain

## Block Data Structure

## Block Validation

# Misc. Components
## ppkeygen.go
A simple application used to generate generate ESDCA public and private key pairings. Outputs the files pubkey and privkey containing the hex-encoded string representation of the keys.

## startminer.sh
A small script used to generate public and private key files, read them, and use them to start an ink-miner.

## shared.go
Contains structures and types used throughout various components of the project.