/*
 * This program implements an ink-miner in the BlockArt project.
 * Usage:
 *		go run ink-miner.go [server ip:port] [pubKey] [privKey]
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/rpc"
	"os"
	"strings"
	"sync"
	"time"

	"./shared"

	"./blockartlib"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES, VARIABLES, CONSTANTS
////////////////////////////////////////////////////////////////////////////////

// For interfacing with other miners
type InkMiner int

var (
	config Config
	// Identity related variables
	Server    *rpc.Client     /* Connection to Server */
	PubKey    ecdsa.PublicKey /* Public and private key pair for validation */
	PrivKey   *ecdsa.PrivateKey
	LocalAddr net.Addr
	Settings  MinerNetSettings
	Ink       uint32
	// Error logging
	errLog *log.Logger = log.New(os.Stderr, "[serv] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
	outLog *log.Logger = log.New(os.Stderr, "[miner] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)

	// Connected miners
	connectedMiners ConnectedMiners = ConnectedMiners{miners: make(map[string]*Miner)}

	// Channel to signal incoming ops, blocks
	opChannel          chan int // int is a placeholder -> may be an op string later
	opComplete         chan int
	recvBlockChannel   chan int
	validationComplete chan int
)

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////

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

type Config struct {
	GenesisBlockHash string `json:"genesis-block-hash"`
}

//TODO FIX TYPES

type Transaction struct {
	// ShapeOp is an application shape operation
	ShapeOp string
	// ShapeOpSig is the signature of the shape operation generated using the private key and the operation
	ShapeOpSig string
	// PubKeyArtNode is the public key of the artnode that generated the op
	PubKeyArtNode string
}

// Block represents a block in the blockchain, contains transactions and metadata
type Block struct {
	// Depth is the position of the block within the blockchain
	Depth uint32
	// Transactions are the list of transactions the block performs
	Transactions []*Transaction
	// PrevBlockHash is the hash of the previous block
	PrevBlockHash string
	// Hash is the hash of the current block
	Hash string
	// PubKeyMiner is the public key of the miner that computed this block
	PubKeyMiner ecdsa.PublicKey
	// Nonce is a 32-bit unsigned integer nonce
	Nonce string
	// Parent is pointer to parent block
	Parent *Block
	// Children is array of pointers to children of block
	Children []*Block
	// Ink is the amount of ink the miner associated with pubkeyminer has
	Ink uint32
}

// Blockchain represents the blockchain, contains an array of Blocks
type Blockchain struct {
	blocks []*Block
}

// Represents a miner. Adapted from server.go
type Miner struct {
	Address         net.Addr
	Key             ecdsa.PublicKey
	RecentHeartbeat int64
	MinerConn       *rpc.Client
}

// Map of all miners currently connected
type ConnectedMiners struct {
	sync.RWMutex
	Miners map[string]*Miner
}

// Basic information on this miner
type MinerInfo struct {
	Address net.Addr
	Key     ecdsa.PublicKey
}

////////////////////////////////////////////////////////////////////////////////
// ERROR HANDLING
////////////////////////////////////////////////////////////////////////////////

func handleErrorFatal(msg string, e error) {
	if e != nil {
		errLog.Fatalf("%s, err = %s\n", msg, e.Error())
	}
}

type ArtNodeInfo struct {
	Transactions []*Transaction
	PubKeyMiner  ecdsa.PublicKey
	Nonce        string
	Ink          uint32
}

////////////////////////////////////////////////////////////////////////////////
// BLOCK FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// // Create a new block
// func NewBlock(depth uint32, transactions string, prevBlockHash string) *Block {
//     block := &Block{
//         Depth: depth,
//         Parent:
//         Children: []*Block,
//         PubKeyMiner:
//         Ink:
//         Transactions: []byte(transactions),
//         PrevBlockHash: prevBlockHash,
//         Hash: []byte{},
//     }
//     block.SetHash()
//     return block
// }

// // NewGenesisBlock creates and returns genesis Block
// func NewGenesisBlock() *Block {
//     block := &Block{
//         Hash: config.GenesisBlockHash,
//         Children: []*Block,
//         Ink: 0,
//         Depth: 0,
//         PrevBlockHash: ""
//     }
//     return block
// }

func ValidateBlock() bool {
	return false
}

func ValidateOperation() bool {
	return false
}

////////////////////////////////////////////////////////////////////////////////
// BLOCKCHAIN FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// AddBlock saves provided data as a block in the blockchain
// func (bc *Blockchain) AddBlock(data string) {
//     // ValidateBlock
//     prevBlock := bc.blocks[len(bc.blocks)-1]
//     newBlock := NewBlock(prevBlock,  data, prevBlock.Hash)
//     bc.blocks = append(bc.blocks, newBlock)
// }

// NewBlockchain creates a new Blockchain with genesis Block
// func NewBlockchain() *Blockchain {
//     return &Blockchain{[]*Block{NewGenesisBlock()}}
// }

////////////////////////////////////////////////////////////////////////////////
// MINER - SERVER
////////////////////////////////////////////////////////////////////////////////
/*
 * Establish a connection to server and attempt to GetNodes
 */

func ConnectServer(serverAddr string) {
	// Tentative method of retrieving local addr
	// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
	var localAddr string
	localHostName, _ := os.Hostname()
	listOfAddr, _ := net.LookupIP(localHostName)
	for _, addr := range listOfAddr {
		if ok := addr.To4(); ok != nil {
			localAddr = ok.String()
		}
	}

	localAddr = fmt.Sprintf("%s%s", localAddr, ":0")

	ln, _ := net.Listen("tcp", localAddr)
	LocalAddr = ln.Addr()

	// TODO:
	// Generating public and private key pairing for now
	// Eventually need to use file parameters
	r, err := os.Open("/dev/urandom")
	key, err := ecdsa.GenerateKey(elliptic.P384(), r)
	PubKey = key.PublicKey
	PrivKey = key
	Ink = 10
	defer r.Close()

	Server, err = rpc.Dial("tcp", serverAddr)
	if err != nil {
		handleErrorFatal("", blockartlib.DisconnectedError(serverAddr))
		return
	}

	outLog.Println("Successfully connected")

	// Register miner on server
	var settings MinerNetSettings
	minerInfo := MinerInfo{LocalAddr, PubKey}
	err = Server.Call("RServer.Register", minerInfo, &settings)
	if err != nil {
		outLog.Println(err)
		return
	}

	// start sending heartbeats
	go sendHeartBeats()

	// start mining noop blocks
	go startMining()

	// Get nodes from server and attempt to connect to them
	GetNodes()

	// TODO:
	// Listen for incoming miner connections
	Inkminer := new(InkMiner)
	miner := rpc.NewServer()
	miner.Register(Inkminer)

	for {
		conn, _ := ln.Accept()
		go miner.ServeConn(conn)
	}
}

/*
 * This function sends heartbeat signals to server to ensure connectivity
 */
func sendHeartBeats() (err error) {
	var ignore bool
	for {
		err = Server.Call("RServer.HeartBeat", PubKey, &ignore)
		if err != nil {
			outLog.Println("Error sending heartbeats.")
			return err
		}
		time.Sleep(time.Millisecond * 5)

	}
}

/* Retrieves a list of new miner addresses from the server
 * Attemps to connect to the new miners it retrieves
 */
func GetNodes() (err error) {
	// Array of miner addresses to be returned by the server
	var addrSet []net.Addr

	outLog.Println("Checking for new miners")
	err = Server.Call("RServer.GetNodes", PubKey, &addrSet)
	if err != nil {
		outLog.Println("Error getting nodes from server.")
		return err
	}

	newMiners := 0

	for _, addr := range addrSet {
		if _, ok := connectedMiners.miners[addr.String()]; !ok && addr != LocalAddr {
			outLog.Println("Connecting to miner...")
			// Attempt to establish connections to retrieved miners
			err = ConnectMiner(addr)
			if err != nil {
				outLog.Println("Could not connect to miner")
			} else {
				newMiners += 1
			}
		} else {
			continue
		}
	}

	outLog.Printf("Connected to %d new ink miners\n", newMiners)

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// MINER - MINER
////////////////////////////////////////////////////////////////////////////////

// Establish RPC connection to other miners
func ConnectMiner(addr net.Addr) (err error) {
	minerAddr := addr.String()
	minerConn, err := rpc.Dial("tcp", minerAddr)
	if err != nil {
		outLog.Printf("Could not reach other miner at %s", minerAddr)
		return err
	}

	args := &MinerInfo{Address: LocalAddr, Key: PubKey}
	reply := MinerInfo{}
	err = minerConn.Call("InkMiner.RegisterMiner", args, &reply)
	if err != nil {
		outLog.Println("Could not intiate intial RPC call to miner")
		return err
	}

	outLog.Println("Connected to miner")

	minerPubKey := reply.Key

	// Register miner to miner map
	connectedMiners.Lock()
	connectedMiners.miners[minerAddr] = &Miner{
		Address:         addr,
		Key:             minerPubKey,
		RecentHeartbeat: time.Now().UnixNano(),
		MinerConn:       minerConn}
	connectedMiners.Unlock()

	outLog.Println("Registered fellow miner")

	// Start sending heartbeat to miner
	go sendMinerHeartbeat(minerConn)
	outLog.Println("Sending heartbeat to fellow miner")

	go monitor(minerAddr, 2*time.Second)
	outLog.Println("Monitoring heartbeat of fellow miner")

	return nil
}

// Register a miner trying to connect as a connected miner
func (m InkMiner) RegisterMiner(args *MinerInfo, reply *MinerInfo) (err error) {
	minerAddr := args.Address
	minerPubKey := args.Key

	outLog.Printf("Miner with address %s trying to connect\n", minerAddr.String())
	*reply = MinerInfo{Address: LocalAddr, Key: PubKey}

	outLog.Println("Attempting to establish return connnection...")

	returnConn, err := rpc.Dial("tcp", minerAddr.String())
	if err != nil {
		outLog.Printf("Could not initiate return connection to connecting miner %s", minerAddr.String())
		return err
	}

	// Register to miner to miner map
	connectedMiners.Lock()
	connectedMiners.miners[minerAddr.String()] = &Miner{
		Address:         minerAddr,
		Key:             minerPubKey,
		RecentHeartbeat: time.Now().UnixNano(),
		MinerConn:       returnConn}
	connectedMiners.Unlock()

	outLog.Println("Return connection established. Miner has been connected")

	// Send heartbeat back to miner
	go sendMinerHeartbeat(returnConn)
	outLog.Println("Sending return heartbeat to connecting miner")

	go monitor(minerAddr.String(), 2*time.Second)
	outLog.Println("Monitoring heartbeat of connecting miner")

	return nil
}

// Validate received block
func (m InkMiner) validateBlock(args *MinerInfo, reply *MinerInfo) (err error) {

}

// Sends heartbeat signals to other miners
func sendMinerHeartbeat(minerConn *rpc.Client) (err error) {
	var ignore bool
	for {
		minerInfo := &MinerInfo{Address: LocalAddr, Key: PubKey}
		err = minerConn.Call("InkMiner.MinerHeartBeat", minerInfo, &ignore)
		if err != nil {
			outLog.Println("Error sending miner heartbeats.", err)
			return err
		}
		time.Sleep(time.Millisecond * 5)
	}
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
			outLog.Printf("%s timed out\n", connectedMiners.miners[minerAddr].Address.String())
			delete(connectedMiners.miners, minerAddr)
			connectedMiners.Unlock()
			return
		}
		connectedMiners.Unlock()
		time.Sleep(heartBeatInterval)
	}
}

////////////////////////////////////////////////////////////////////////////////
// MINER CALLS
////////////////////////////////////////////////////////////////////////////////

// Return string version of public key
func pubKeyToString(pubKey ecdsa.PublicKey) string {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	encodedBytes := hex.EncodeToString(pubKeyBytes)
	return encodedBytes
}

// Mine op block, or validate block by creating block
// Creation of noop blocks broken up to check for received ops or blocks
// hash is a hash of [prev-hash, op, op-signature, pub-key, nonce]
func startMining() {
	// vars needed to create noop block
	var depth, ink uint32
	var prevBlockHash, nonce, hash string

	// Channels
	opChannel = make(chan int, 3)
	OpComplete = make(chan int, 3)
	recvBlockChannel = make(chan int, 3)
	validationComplete = make(chan int, 3)

	for {
	findLongestBranch:
		select {
		case <-opChannel:
			<-opComplete
			goto findLongestBranch
		case <-recvBlockChannel:
			<-validationComplete
			goto findLongestBranch
		default:
			//TODO: Get leaf in longest chain
			//TODO: Set the variables above
		}

		select {
		case <-opChannel:
			<-opComplete
			goto findLongestBranch
		case <-recvBlockChannel:
			<-validationComplete
			goto findLongestBranch
		default:
			// Get the value of new hash block and nonce
			pubKeyString = pubKeyToString(PubKey)
			contents := fmt.Sprintf("%s%s", prevHash, pkeyString)
			nonce, hash = getNonce(contents, Settings.PoWDifficultyNoOpBlock)
		}
		select {
		case <-opChannel:
			<-opComplete
			goto findLongestBranch
		case <-recvBlockChannel:
			<-validationComplete
			goto findLongestBranch
		default:
			// Create block, send block to miners, add to blockchain, increase ink supply
			block := &Block{
				Hash:          hash,
				Depth:         uint32(depth + 1),
				PrevBlockHash: prevHash,
				PubKeyMiner:   pubKeyString,
				Nonce:         nonce,
				Ink:           ink + Settings.InkPerNoOpBlock,
			}
			sendBlock(block)
			append(BlockchainRef.Blocks, block)
			Ink += Settings.InkPerNoOpBlock

			// Update last block
			BlockchainRef.LastBlock = block
		}
	}
}

// Return nonce and hash made with nonce that has required 0s
func getNonce(blockHash string, difficulty int64) (string, string) {
	wantedString := strings.Repeat("0", int(difficulty))
	var h string

	for {
		randNum := rand.Intn(23)
		secret := make([]byte, randNum)
		for i := 0; i < randNum; i++ {
			secret[i] = letters[rand.Intn(len(letters))]
		}

		h = computeNonceSecretHash(blockHash, string(secret))

		if strings.HasSuffix(h, wantedString) {
			return string(secret), h
		}
	}
}

// Helper: Returns MD5 hash of given hash + secret
func computeNonceSecretHash(nonce string, secret string) string {
	h := md5.New()
	h.Write([]byte(nonce + secret))
	str := hex.EncodeToString(h.Sum(nil))
	return str
}

// Send newly created block to all connected miners to be validated
func sendBlock(block *Block) {
	b, err := json.Marshal(block)
	if err != nil {
		outlog.Printf("Error marshalling block into string:%s\n", err)
	}
	var m []string
	var reply *bool
	for _, value := range connectedMiners.miners {
		value.Call("RServer.ValidateBlock", b, reply)
	}
}

////////////////////////////////////////////////////////////////////////////////
// MINER - ARTIST NODE
////////////////////////////////////////////////////////////////////////////////
// Check that key of incoming art node matches key of miner.
func (m InkMiner) RegisterArtNode(Key ecdsa.PublicKey, settings *CanvasSettings) (err error) {
	// Commented out for now because test app generates its own key
	// if PubKey != Key {
	// 	return errors.New("Mismatch between Public Keys")
	// }
	*settings = Settings.CanvasSettings
	return nil
}

func (m InkMiner) GetInk(args shared.Reply, reply *shared.Reply) (err error) {
	*reply = shared.Reply{InkRemaining: Ink}
	return nil
}

// TODO ADD TO BLOCKCHAIN
func (m InkMiner) AddShape(args *shared.AddShapeInfo, reply *shared.AddShapeResponse) (err error) {

	Ink = Ink - args.InkRequired
	*reply = shared.AddShapeResponse{InkRemaining: Ink}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// MAIN, LOCAL
////////////////////////////////////////////////////////////////////////////////

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// check for correct arguments
	args := os.Args
	if len(args) != 4 {
		fmt.Println("Usage: go run ink-miner.go [server ip:port] [pubKey] [privKey]")
		return
	}
	serverAddr := args[1]

	ConnectServer(serverAddr)
}
