/*
 * This program implements an ink-miner in the BlockArt project.
 * Usage:
 *		go run ink-miner.go [server ip:port] [pubKey] [privKey]
 */

package main

import (
	"os"
	"fmt"
	"net/rpc"
	"net"
	"crypto/ecdsa"
	"encoding/gob"
	"crypto/elliptic"
	"time"
	"sync"

	"./blockartlib"
	"log"
)

type InkMiner int

var(
	// Identity related variables
	Server 			*rpc.Client				/* Connection to Server */
	PubKey			ecdsa.PublicKey			/* Public and private key pair for validation */
	PrivKey			*ecdsa.PrivateKey
	LocalAddr 		net.Addr

	// Error logging
	errLog          *log.Logger = log.New(os.Stderr, "[serv] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)

	// Connected mineres
	connectedMiners ConnectedMiners = ConnectedMiners{miners: make(map[string]*Miner)}
)


func main(){
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// check for correct arguments
	args := os.Args

	if len(args) != 5 {
		fmt.Println("Usage: go run ink-miner.go [server ip:port] [local ip:port] [pubKey] [privKey]")
		return
	}
	serverAddr := args[1]
	localAddr := args[2]
	ln, _ := net.Listen("tcp", localAddr)
	LocalAddr = ln.Addr()

	// TODO:
	// Generating public and private key pairing for now
	// Eventually need to use file parameters
	r, err := os.Open("/dev/urandom")
	key, err := ecdsa.GenerateKey(elliptic.P384(), r)
	PubKey = key.PublicKey
	PrivKey = key
	defer r.Close()

	Server, err = rpc.Dial("tcp", serverAddr)
	if err != nil {
		handleErrorFatal("", blockartlib.DisconnectedError(serverAddr))
		return
	}

	fmt.Println("Successfully connected")

	// Register miner on server
	var settings MinerNetSettings
	err = Server.Call("RServer.Register", MinerInfo{LocalAddr, PubKey}, &settings)
	if err != nil{
		fmt.Println(err)
		return
	}

	// start sending heartbeats
	go sendHeartBeats()

	// Get nodes from server and attempt to connect to them
	GetNodes()

	// TODO:
	// Listen for incoming miner connections
	Inkminer := new(InkMiner)
	miner := rpc.NewServer()
	miner.Register(Inkminer)

	for{
		conn, _ := ln.Accept()
		go miner.ServeConn(conn)
	}


}

/*
 * This function sends heartbeat signals to server to ensure connectivity
 */
func sendHeartBeats() (err error){
	var ignore bool
	for{
		err = Server.Call("RServer.HeartBeat", PubKey, &ignore)
		if err != nil {
			fmt.Println("Error sending heartbeats.")
			return err
		}
		time.Sleep(time.Millisecond * 5)

	}
	return nil
}


type MinerInfo struct {
	Address net.Addr
	Key     ecdsa.PublicKey
}

// Settings for a canvas in BlockArt.
type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32 `json:"canvas-x-max"`
	CanvasYMax uint32 `json:"canvas-y-max"`
}

type MinerSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string `json:"genesis-block-hash"`

	// The minimum number of ink miners that an ink miner should be
	// connected to.
	MinNumMinerConnections uint8 `json:"min-num-miner-connections"`

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32 `json:"ink-per-op-block"`
	InkPerNoOpBlock uint32 `json:"ink-per-no-op-block"`

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32 `json:"heartbeat"`

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8 `json:"pow-difficulty-op-block"`
	PoWDifficultyNoOpBlock uint8 `json:"pow-difficulty-no-op-block"`
}

// Settings for an instance of the BlockArt project/network.
type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string `json:"genesis-block-hash"`

	// The minimum number of ink miners that an ink miner should be
	// connected to.
	MinNumMinerConnections uint8 `json:"min-num-miner-connections"`

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32 `json:"ink-per-op-block"`
	InkPerNoOpBlock uint32 `json:"ink-per-no-op-block"`

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32 `json:"heartbeat"`

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8 `json:"pow-difficulty-op-block"`
	PoWDifficultyNoOpBlock uint8 `json:"pow-difficulty-no-op-block"`

	// Canvas settings
	CanvasSettings CanvasSettings `json:"canvas-settings"`
}

func handleErrorFatal(msg string, e error) {
	if e != nil {
		errLog.Fatalf("%s, err = %s\n", msg, e.Error())
	}
}

////////////////////////////////////////////////////////////////////////////////
// CALLS TO SERVER
////////////////////////////////////////////////////////////////////////////////

/* Retrieves a list of new miner addresses from the server
 * Attemps to connect to the new miners it retrieves
 */
func GetNodes() (err error) {
	// Array of miner addresses to be returned by the server
	var addrSet []net.Addr

	fmt.Println("Checking for new miners")
	err = Server.Call("RServer.GetNodes", PubKey, &addrSet)
	if err != nil {
		fmt.Println("Error getting nodes from server.")
		return err
	}

	newMiners := 0

	for _, addr := range addrSet {
		if _, ok := connectedMiners.miners[addr.String()]; !ok && addr != LocalAddr {
			fmt.Println("Connecting to miner...")
			// Attempt to establish connections to retrieved miners
			err = ConnectMiner(addr)
			if err != nil {
				fmt.Println("Could not connect to miner")
			} else {
				newMiners += 1
			}
		} else {
			continue
		}
	}

	fmt.Printf("Connected to %d new ink miners\n", newMiners)

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// CALLS TO MINERS
////////////////////////////////////////////////////////////////////////////////
// Represents a miner. Adapted from server.go
type Miner struct {
	Address 			net.Addr
	Key 				ecdsa.PublicKey
	RecentHeartbeat 	int64
	MinerConn 			*rpc.Client
}

// Map of all miners currently connected
type ConnectedMiners struct {
	sync.RWMutex
	miners map[string]*Miner
}

// Establish RPC connection to other miners
func ConnectMiner(addr net.Addr) (err error) {
	minerAddr := addr.String()
	minerConn, err := rpc.Dial("tcp", minerAddr)
	if err != nil {
		fmt.Printf("Could not reach other miner at %s", minerAddr)
		return err
	}

	args := &MinerInfo{Address: LocalAddr, Key: PubKey}
	reply := MinerInfo{}
	err = minerConn.Call("InkMiner.RegisterMiner", args, &reply)
	if err != nil {
		fmt.Println("Could not intiate intial RPC call to miner")
		return err
	}

	fmt.Println("Connected to miner")

	minerPubKey := reply.Key

	// Register miner to miner map
	connectedMiners.Lock()
	connectedMiners.miners[minerAddr] = &Miner{
		Address: addr,
		Key: minerPubKey,
		RecentHeartbeat: time.Now().UnixNano(),
		MinerConn: minerConn}
	connectedMiners.Unlock()

	fmt.Println("Registered fellow miner")

	// Start sending heartbeat to miner
	go SendMinerHeartbeat(minerConn)
	fmt.Println("Sending heartbeat to fellow miner")

	go monitor(minerAddr, 2*time.Second)
	fmt.Println("Monitoring heartbeat of fellow miner")

	return nil
}

// Register a miner trying to connect as a connected miner
func (m InkMiner) RegisterMiner(args *MinerInfo, reply *MinerInfo) (err error) {
	minerAddr := args.Address
	minerPubKey := args.Key

	fmt.Printf("Miner with address %s trying to connect\n", minerAddr.String())
	*reply = MinerInfo{Address: LocalAddr, Key: PubKey}
	
	fmt.Println("Attempting to establish return connnection...")

	returnConn, err := rpc.Dial("tcp", minerAddr.String())
	if err != nil {
		fmt.Printf("Could not initiate return connection to connecting miner %s", minerAddr.String())
		return err
	}

	// Resgister to miner to miner map
	connectedMiners.Lock()
	connectedMiners.miners[minerAddr.String()] = &Miner{
		Address: minerAddr,
		Key: minerPubKey,
		RecentHeartbeat: time.Now().UnixNano(),
		MinerConn: returnConn}
	connectedMiners.Unlock()

	fmt.Println("Return connection established. Miner has been connected")

	// Send heartbeat back to miner
	go SendMinerHeartbeat(returnConn)
	fmt.Println("Sending return heartbeat to connecting miner")

	go monitor(minerAddr.String(), 2*time.Second)
	fmt.Println("Monitoring heartbeat of connecting miner")

	return nil
}

// Sends heartbeat signals to other miners
func SendMinerHeartbeat(minerConn *rpc.Client) (err error) {
	var ignore bool
	for {
		minerInfo := &MinerInfo{Address: LocalAddr, Key: PubKey}
		err = minerConn.Call("InkMiner.MinerHeartBeat", minerInfo, &ignore)
		if err != nil {
			fmt.Println("Error sending miner heartbeats.", err)
			return err
		}
		time.Sleep(time.Millisecond * 5)
	}
	return nil
}

// Updates heartbeats for miners. Adapted from server.go
func (m InkMiner) MinerHeartBeat(minerInfo *MinerInfo, _ignored *bool) (err error) {
	connectedMiners.Lock()
	defer connectedMiners.Unlock()
	minerAddr := minerInfo.Address.String()
	if _, ok := connectedMiners.miners[minerAddr]; !ok {
		return err
	}

	connectedMiners.miners[minerAddr].RecentHeartbeat = time.Now().UnixNano()

	return nil
}

// Deletes dead miners. Adapted from server.go
func monitor(minerAddr string, heartBeatInterval time.Duration) {
	for {
		connectedMiners.Lock()
		if time.Now().UnixNano()-connectedMiners.miners[minerAddr].RecentHeartbeat > int64(heartBeatInterval) {
			fmt.Printf("%s timed out\n", connectedMiners.miners[minerAddr].Address.String())
			delete(connectedMiners.miners, minerAddr)
			connectedMiners.Unlock()
			return
		}
		connectedMiners.Unlock()
		time.Sleep(heartBeatInterval)
	}
}



////////////////////////////////////////////////////////////////////////////////
// CALLS TO ARTISTS
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// LOCAL
////////////////////////////////////////////////////////////////////////////////
func pubKeyToString(key ecdsa.PublicKey) string {
	return string(elliptic.Marshal(key.Curve, key.X, key.Y))
}