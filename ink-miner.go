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
	"errors"
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
	Server        *rpc.Client     /* Connection to Server */
	PubKey        ecdsa.PublicKey /* Public and private key pair for validation */
	PrivKey       *ecdsa.PrivateKey
	LocalAddr     net.Addr
	Settings      MinerNetSettings
	BlockchainRef *Blockchain
	Ink           uint32
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

type Op struct {
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
	Ops []*Op
	// PrevBlockHash is the hash of the previous block
	PrevBlockHash string
	// Hash is the hash of the current block
	Hash string
	// PubKeyMiner is the public key of the miner that computed this block
	PubKeyMiner ecdsa.PublicKey
	// Nonce is a 32-bit unsigned integer nonce
	Nonce string
	// Ink is the amount of ink the miner associated with pubkeyminer has
	Ink uint32
}

// Blockchain represents the blockchain, contains an array of Blocks
type Blockchain struct {
	Blocks    []*Block
	LastBlock *Block
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
	Ops         []*Op
	PubKeyMiner ecdsa.PublicKey
	Nonce       string
	Ink         uint32
}

////////////////////////////////////////////////////////////////////////////////
// BLOCK FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// Create a new block
func NewBlock(prevBlock Block, hash string, nonce string) *Block {
	block := &Block{
		Depth:       prevBlock.Depth + 1,
		Parent:      &prevBlock,
		PubKeyMiner: PubKey,
		Ink:         Ink,
		// Ops:
		PrevBlockHash: prevBlock.Hash,
		Hash:          hash,
		Nonce:         nonce,
	}
	return block
}

// // NewGenesisBlock creates and returns genesis Block
func NewGenesisBlock() *Block {
	block := &Block{
		Hash:          config.GenesisBlockHash,
		Ink:           0,
		Depth:         0,
		PrevBlockHash: "",
	}
	return block
}

func ValidateOperation() bool {
	return false
}

////////////////////////////////////////////////////////////////////////////////
// BLOCKCHAIN FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// AddBlock saves provided data as a block in the blockchain
// Block has been validated
// data is a json encoded string
func AddBlock(nonce string, data string) {
	prevBlock := BlockchainRef.Blocks[len(BlockchainRef.Blocks)-1]
	newBlock := NewBlock(*prevBlock, data, nonce)
	BlockchainRef.Blocks = append(BlockchainRef.Blocks, newBlock)
	// store reference to last block
	BlockchainRef.LastBlock = newBlock
}

//NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain() *Blockchain {
	genesisBlock := NewGenesisBlock()
	return &Blockchain{
		Blocks:    []*Block{genesisBlock},
		LastBlock: genesisBlock,
	}
}

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

	// Store miner settings from sever
	Settings = settings

	// Start sending heartbeats
	go sendHeartBeats()

	// start mining noop blocks
	go startMining()

	// Get nodes from server and attempt to connect to them
	err = GetNodes()
	if err != nil {
		outLog.Println("Error getting nodes from server: ", err)
		return
	}

	// Monitor the miner threshold
	go monitorThreshold()

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

/* Monitors the current number of miners connected to this miner
 * If the number of miners is below the minimum, we will keep pinging the server
 * until we have the required number of miners to keep working
 *
 * TODO: This will need to be extended to stop/pause mining and other activities
 *       whenever we fall below the min threshold
 */
func monitorThreshold() {
	for {
		connectedMiners.Lock()
		numConnectedMiners := len(connectedMiners.miners)
		connectedMiners.Unlock()
		threshold := int(Settings.MinNumMinerConnections)

		if numConnectedMiners < threshold {
			outLog.Printf("Number of connected miners: %d\n", numConnectedMiners)
			outLog.Printf("Threshold: %d\n", threshold)
			outLog.Println("We are below the minimum miner threshold!")

			err := GetNodes()
			if err != nil {
				outLog.Println("Error getting nodes from server: ", err)
			}

		} else {
			continue
		}

		// Wait before checking again
		time.Sleep(2 * time.Second)
	}
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
func (m InkMiner) validateBlock(args *shared.BlockArgs, reply *shared.BlockArgs) (err error) {
	// Send signal to channel that block was received
	recvBlockChannel <- 1

	// Turn json string into struct
	var block Block
	err = json.Unmarshal(args.BlockString, block)

	// Check that block hasn't been repeated, check from end first
	for i := range len(BlockchainRef.Blocks) {
		b := BlockchainRef.Blocks[i]
		if b.Hash == block.Hash {
			return errors.New("Repeated block")
		}
	}

	// Check that nonce is correct
	err = checkNonce(block)
	if err != nil {
		return errors.New("Bad nonce")
	}

	// Check for valid signature
	err = checkValidSignature(block)

	// Check if valid parent
	err = checkValidParent(block)

	// Add to blockchain, update last block
	BlockchainRef.Blocks = append(BlockchainRef.Blocks, block)
	BlockchainRef.LastBlock = block

	//TODO:
	// Update ink amounts

	//TODO:
	// Send block to connected miners

	// Send signal to channel that block validation is complete
	validationComplete <- 1
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

// Turn public key string to public key type
func stringToPubKey(pubString string) *ecdsa.PublicKey {
	pKey, _ := hex.DecodeString(pubString)
	key, _ := x509.ParseECPrivateKey(pKey)
	return key
}

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
			//Get leaf and info above
			lastBlock := BlockchainRef.LastBlock
			depth = lastBlock.Depth
			ink = lastBlock.Ink
			prevBlockHash = lastBlock.Hash
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

// Return false if nonce validation fails
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

// Returns MD5 hash of given nonce + blockContents
func computeNonceSecretHash(nonce string, secret string) string {
	h := md5.New()
	h.Write([]byte(nonce + secret))
	str := hex.EncodeToString(h.Sum(nil))
	return str
}

// Return error if nonce given does not compute block hash or if wrong difficulty
func checkNonce(block *Block) error {
	secret := ""
	difficulty := Settings.PoWDifficultyNoOpBlock

	// Get public key as string
	pubKeyString := pubKeyToString(block.PubKeyMiner)

	// If there are ops, include in secret
	ops := block.Ops
	numOps := len(block.Ops)
	if numOps > 0 {
		difficulty = Settings.PoWDifficultyOpBlock
		for i := range numOps {
			secret = fmt.Sprintf("%s%s%s", secret, ops[i].ShapeOp, ops[i].ShapeOpSig)
		}
	}

	// Compute secret
	secret = fmt.Sprintf("%s%s%s", block.PrevBlockHash, secret, pubKeyString)

	// Check if string + nonce = hash
	hash := computeNonceSecretHash(block.Nonce, secret)
	if hash != block.Hash {
		return errors.New("Incorrect hash")
	}

	// Check if hash has right difficulty
	wantedString := strings.Repeat("0", int(difficulty))
	if !strings.HasSuffix(hash, wantedString) {
		return errors.New("Wrong difficulty")
	}

	return nil
}

//  Check if block has a valid signatures for the ops
func checkValidSignature(block *Block) error {
	ops := block.Ops
	for i := range len(block.Ops) {
		pkey := ops[i].PubKeyArtNode
		if !ecdsa.Verify(pkey, ops[i].ShapeOpSig, pkey.X, pkey.Y) {
			return errors.New("Op signature does not match")
		}
	}
}

// Return error if block does not have valid parent in blockchain
func checkValidParent(block *Block) error {
	for i := len(BlockchainRef.Blocks) - 1; i >= 0; i-- {
		if block.PrevBlockHash == BlockchainRef.Blocks.Hash {
			return nil
		}
	}
	return errors.New("Parent does not exist")
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
		value.Call("InkMiner.ValidateBlock", b, reply)
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

// Return genesis block to art node
func (m InkMiner) GetGenesisBlock(_ignored string, hash *string) (err error){
	*hash = Settings.GenesisBlockHash
	return nil
}

func (m InkMiner) GetShape(shapeHash string, shape *shared.ShapeOp) (err error){
	fmt.Println(BlockchainRef)
	for i := range BlockchainRef.Blocks {
		ops := BlockchainRef.Blocks[i].Ops
		for j:= range ops {
			if ops[j].ShapeOpSig == shapeHash {
				*shape = ops[j].ShapeOp
				return nil
			}
		}
	}
	fmt.Println("Could not get shape in blockchain.")
	return blockartlib.InvalidShapeHashError(shapeHash)
}

// TODO ADD TO BLOCKCHAIN
func (m InkMiner) AddShape(args *shared.AddShapeInfo, reply *shared.AddShapeResponse) (err error) {

	// todo when should ink actually be updated?
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

	// if sole miner, create blockchain
	BlockchainRef = NewBlockchain()

	// else request blockchain from other miners
}
