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
	inkMap        map[string]uint32 // map pubkeyminer to inkremaining
	// Error logging
	errLog *log.Logger = log.New(os.Stderr, "[serv] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
	outLog *log.Logger = log.New(os.Stderr, "[miner] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)

	// Connected miners
	connectedMiners ConnectedMiners = ConnectedMiners{Miners: make(map[string]*Miner)}

	// Channel to signal incoming ops, blocks
	opChannel          chan int // int is a placeholder -> may be an op string later
	opComplete         chan int
	recvBlockChannel   chan int
	validationComplete chan int
	powComplete        chan int
	opBlockCreation    chan int
	opBlockCreated     chan int
	opBlockSend        chan int
	opBlockSent        chan int
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

// Block represents a block in the blockchain, contains transactions and metadata
type Block struct {
	// Depth is the position of the block within the blockchain
	Depth uint32
	// Transactions are the list of transactions the block performs
	Ops []*shared.Op
	// PrevBlockHash is the hash of the previous block
	PrevBlockHash string
	// Hash is the hash of the current block
	Hash string
	// PubKeyMiner is the public key of the miner that computed this block
	PubKeyMiner ecdsa.PublicKey
	// Nonce is a 32-bit unsigned integer nonce
	Nonce string
}

// Blockchain represents the blockchain, contains an array of Blocks
type Blockchain struct {
	sync.RWMutex
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
	Ops         []*shared.Op
	PubKeyMiner ecdsa.PublicKey
	Nonce       string
	Ink         uint32
}

////////////////////////////////////////////////////////////////////////////////
// BLOCK FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// // NewGenesisBlock creates and returns genesis Block
func NewGenesisBlock() *Block {
	block := &Block{
		Hash:          config.GenesisBlockHash,
		Depth:         0,
		PrevBlockHash: "",
	}
	return block
}

////////////////////////////////////////////////////////////////////////////////
// BLOCKCHAIN FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// AddBlock saves provided data as a block in the blockchain
// Block has been validated
// data is a json encoded string
// func AddBlock(nonce string, data string) {
// 	prevBlock := BlockchainRef.Blocks[len(BlockchainRef.Blocks)-1]
// 	newBlock := NewBlock(*prevBlock, data, nonce)
// 	BlockchainRef.Blocks = append(BlockchainRef.Blocks, newBlock)
// 	// store reference to last block
// 	BlockchainRef.LastBlock = newBlock
// }

//NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain() *Blockchain {
	genesisBlock := NewGenesisBlock()
	return &Blockchain{
		Blocks:    []*Block{genesisBlock},
		LastBlock: genesisBlock,
	}
}

// TODO
// disseminate op
// Send validated op to all connected miners
func sendOp(op *shared.Op) {
	b, err := json.Marshal(op)
	if err != nil {
		outLog.Printf("Error marshalling op into string:%s\n", err)
	}
	//var m []string
	var reply *bool
	for _, value := range connectedMiners.Miners {
		value.MinerConn.Call("InkMiner.ReceiveOp", b, reply)
	}
}

func (m InkMiner) ReceiveOp(op *shared.Op, reply *bool) error {
	// send signal to channel that op was received
	opChannel <- 1
	// do POW
	fmt.Println("DOING POW")
	// TODO get contents here
	//contents := fmt.Sprintf("%s%s", prevHash, pkeyString)

	// nonce, hash := getNonce(contents, Settings.PoWDifficultyOpBlock)
	powComplete <- 1
	opBlockCreation <- 1
	// pkeyString := pubKeyToString(PubKey)
	// create Op block
	fmt.Println("CREATING BLOCK")
	opBlockCreated <- 1
	opBlockSend <- 1
	fmt.Println("SENDING BLOCK")
	//sendBlock()
	opBlockSent <- 1
	return nil
}

// Validate operation from artnode
func validateOp(op *shared.Op) error {

	// check that op's ink required < GetMinerInk()

	err := checkEnoughInk(op)
	if err != nil {
		return err
	}
	// check that op with identical signature doesn't exist
	err = checkOpExists(op)
	if err != nil {
		return err
	}
	// check no intersects
	err = checkOpIntersects(op)
	if err != nil {
		return err
	}
	// if op is delete op, check that original op exists
	err = checkOpDeleteInvalid(op)
	if err != nil {
		return err
	}

	return nil
}

//
func checkEnoughInk(op *shared.Op) error {
	if op.InkRequired > GetMinerInk(op.PubKeyArtNode) {
		return errors.New("Not enough ink")
	}
	return nil
}

// check whether identical op has not already been added to the chain
func checkOpExists(op *shared.Op) error {
	pubKey := op.PubKeyArtNode
	for k := 0; k < len(BlockchainRef.Blocks); k++ {
		block := BlockchainRef.Blocks[k]
		ops := block.Ops
		for i := 0; i < len(block.Ops); i++ {
			pkey := ops[i].PubKeyArtNode
			if pkey == pubKey {
				return errors.New("Op already exists in blockchain")
			}
		}
	}
	return nil
}

// TODO
func checkOpIntersects(op *shared.Op) error {
	return nil
}

// TODO
func checkOpDeleteInvalid(op *shared.Op) error {
	return nil
}

// Get Ink remaining for miner associated with pubKey
func GetMinerInk(pubKey string) uint32 {
	ink, ok := inkMap[pubKey]
	if !ok {
		// could not find miner in inkMap so ink amount is 0
		return 0
	}
	return ink
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

	ln, err := net.Listen("tcp", localAddr)
	LocalAddr = ln.Addr()

	// TODO:
	// Generating public and private key pairing for now
	// Eventually need to use file parameters
	r, err := os.Open("/dev/urandom")
	key, err := ecdsa.GenerateKey(elliptic.P384(), r)
	PubKey = key.PublicKey
	PrivKey = key
	// initialize ink map for current miner
	inkMap[pubKeyToString(PubKey)] = 0
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
	//go startMining()

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
		if _, ok := connectedMiners.Miners[addr.String()]; !ok && addr != LocalAddr {
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
		numConnectedMiners := len(connectedMiners.Miners)
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
	connectedMiners.Miners[minerAddr] = &Miner{
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
	connectedMiners.Miners[minerAddr.String()] = &Miner{
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

// Validate received block, also check longest path
func (m InkMiner) validateBlock(args *shared.BlockArgs, reply *shared.BlockArgs) (err error) {
	// Send signal to channel that block was received
	recvBlockChannel <- 1

	// Turn json string into struct
	var block Block
	err = json.Unmarshal([]byte(args.BlockString), block)
	if err != nil {
		outLog.Printf("Couldn't unmarshal block string:%s\n", err)
	}

	// Check that block hasn't been repeated, check from end first
	BlockchainRef.Lock()
	for i := 0; i < len(BlockchainRef.Blocks); i++ {
		b := BlockchainRef.Blocks[i]
		if b.Hash == block.Hash {
			validationComplete <- 1
			BlockchainRef.Unlock()
			return errors.New("Repeated block")
		}
	}
	BlockchainRef.Unlock()

	// Check depth of received block
	BlockchainRef.Lock()
	depth := BlockchainRef.LastBlock.Depth
	BlockchainRef.Unlock()

	if depth >= block.Depth {
		validationComplete <- 1
		return errors.New("Block is not addition to longest chain")
	} else {
		// If depth difference greater than 1 then get longest chain from neighbours
		if (block.Depth - depth) > 1 {
			// Get longest chain
			getLongestChain()
		}
	}

	// Check that nonce is correct
	err = checkNonce(&block)
	if err != nil {
		validationComplete <- 1
		return errors.New("Bad nonce")
	}

	// Check for valid signature
	err = checkValidSignature(&block)
	if err != nil {
		validationComplete <- 1
		return errors.New("Bad signature")
	}

	// Check if valid parent
	err = checkValidParent(&block)
	if err != nil {
		validationComplete <- 1
		return errors.New("Bad parent")
	}

	// Add to blockchain, update last block
	BlockchainRef.Lock()
	BlockchainRef.Blocks = append(BlockchainRef.Blocks, &block)
	BlockchainRef.LastBlock = &block
	BlockchainRef.Unlock()

	// Update ink amounts
	updateInk(&block)

	// Send block to connected miners
	sendBlock(&block)

	// Send signal to channel that block validation is complete
	validationComplete <- 1

	return nil
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
	if _, ok := connectedMiners.Miners[minerAddr]; !ok {
		return err
	}

	connectedMiners.Miners[minerAddr].RecentHeartbeat = time.Now().UnixNano()

	return nil
}

// Deletes dead miners. Adapted from server.go
func monitor(minerAddr string, heartBeatInterval time.Duration) {
	for {
		connectedMiners.Lock()
		if time.Now().UnixNano()-connectedMiners.Miners[minerAddr].RecentHeartbeat > int64(heartBeatInterval) {
			outLog.Printf("%s timed out\n", connectedMiners.Miners[minerAddr].Address.String())
			delete(connectedMiners.Miners, minerAddr)
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
	decodedKey, _ := x509.ParsePKIXPublicKey(pKey)
	key := decodedKey.(*ecdsa.PublicKey)
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
	//vars needed to create noop block
	var depth uint32
	var prevBlockHash string
	var nonce string
	var hash string
	var pKeyString string

	// Channels
	opChannel = make(chan int, 3)
	powComplete = make(chan int, 3)
	opBlockCreation = make(chan int, 3)
	opBlockCreated = make(chan int, 3)
	opBlockSend = make(chan int, 3)
	opBlockSent = make(chan int, 3)
	recvBlockChannel = make(chan int, 3)
	validationComplete = make(chan int, 3)

	for {
	findLongestBranch:
		select {
		case <-opChannel:
			<-powComplete //pow complete and created opblock
			goto findLongestBranch
		case <-recvBlockChannel:
			<-validationComplete
			goto findLongestBranch
		default:
			//Get leaf and info above
			BlockchainRef.Lock()
			lastBlock := BlockchainRef.LastBlock
			BlockchainRef.Unlock()
			depth = lastBlock.Depth
			prevBlockHash = lastBlock.Hash
		}
		select {
		case <-opChannel:
			<-powComplete
			goto findLongestBranch
		case <-opBlockCreation:
			<-opBlockCreated
			goto findLongestBranch
		case <-opBlockSend:
			<-opBlockSent
			goto findLongestBranch
		case <-recvBlockChannel:
			<-validationComplete
			goto findLongestBranch
		default:
			// Get the value of new hash block and nonce
			pKeyString = pubKeyToString(PubKey)
			contents := fmt.Sprintf("%s%s", prevBlockHash, pKeyString)
			getNonce(contents, Settings.PoWDifficultyNoOpBlock)
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
				PrevBlockHash: prevBlockHash,
				PubKeyMiner:   PubKey,
				Nonce:         nonce,
			}
			sendBlock(block)
			BlockchainRef.Lock()
			BlockchainRef.Blocks = append(BlockchainRef.Blocks, block)
			BlockchainRef.Unlock()
			ink := inkMap[pKeyString]
			inkMap[pKeyString] = (ink + Settings.InkPerNoOpBlock)

			// Update last block
			BlockchainRef.Lock()
			BlockchainRef.LastBlock = block
			BlockchainRef.Unlock()
		}
	}
}

// Return false if nonce validation fails
// Return nonce and hash made with nonce that has required 0s
func getNonce(blockHash string, difficulty uint8) (string, string) {
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
		for i := 0; i <= numOps; i++ {
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
	for i := 0; i <= len(block.Ops); i++ {
		pkey := stringToPubKey(ops[i].PubKeyArtNode)
		op := ops[i]
		if !ecdsa.Verify(pkey, []byte(op.ShapeOp.ShapeSvgString), op.ShapeOpSig.R, op.ShapeOpSig.S) {
			return errors.New("Op signature does not match")
		}
	}

	return nil
}

// Return error if block does not have valid parent in blockchain
func checkValidParent(block *Block) error {
	BlockchainRef.Lock()
	for i := len(BlockchainRef.Blocks) - 1; i >= 0; i-- {
		if block.PrevBlockHash == BlockchainRef.Blocks[i].Hash {
			BlockchainRef.Unlock()
			return nil
		}
	}
	BlockchainRef.Unlock()
	return errors.New("Parent does not exist")
}

// Send newly created block to all connected miners to be validated
func sendBlock(block *Block) {
	b, err := json.Marshal(block)
	if err != nil {
		outLog.Printf("Error marshalling block into string:%s\n", err)
	}

	var reply *bool
	for _, value := range connectedMiners.Miners {
		value.MinerConn.Call("InkMiner.ValidateBlock", b, reply)
	}
}

// Update ink amounts of miners
func updateInk(block *Block) {
	pubKey := pubKeyToString(block.PubKeyMiner)
	minerInk := inkMap[pubKey]

	// If ops exist, credit and debit ink to miners
	for i := 0; i < len(block.Ops); i++ {
		OpMinerInk := inkMap[block.Ops[i].PubKeyArtNode]
		inkMap[block.Ops[i].PubKeyArtNode] = OpMinerInk - block.Ops[i].InkRequired
		inkMap[pubKey] = minerInk + Settings.InkPerOpBlock
		return
	}
	// Else add ink to miner that mined block
	inkMap[pubKey] = minerInk + Settings.InkPerNoOpBlock
}

// Get longest chain from connected miners
func getLongestChain() {
	depth := uint32(0)
	var conn *rpc.Client

	for _, value := range connectedMiners.Miners {
		var reply shared.BlockArgs
		var b *Block
		value.MinerConn.Call("InkMiner.getLatestBlock", &reply, &reply)
		err := json.Unmarshal([]byte(reply.BlockString), b)
		if err != nil {
			outLog.Printf("Error unmarshalling latest block")
		}
		if b.Depth > depth {
			depth = b.Depth
			conn = value.MinerConn
		}
	}

	// TODO
	// Get map of index:hash
	var reply shared.BlockArgs

	conn.Call("InkMiner.getChain", &reply, &reply)

	// Compare hashes starting from end of map
	// Remove differing block
	// Go through index and get single blocks
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

func (m InkMiner) GetInk(args shared.Message, reply *shared.Message) (err error) {
	publicKey := pubKeyToString(args.PublicKey)
	*reply = shared.Message{InkRemaining: GetMinerInk(publicKey)}
	return nil
}

// TODO ADD TO BLOCKCHAIN
func (m InkMiner) AddShape(op *shared.Op, reply *shared.AddShapeResponse) (err error) {
	// validate op myself
	error := validateOp(op)
	if error != nil {
		reply.Err = error
	}

	// send validated op to neighbours so that they start mining
	sendOp(op)

	// start POW myself too
	// by sending channel interrupt

	return nil
}

// Return block with largest depth
func (m InkMiner) getLatestBlock(args *shared.BlockArgs, reply *shared.BlockArgs) (err error) {
	BlockchainRef.Lock()
	block := BlockchainRef.LastBlock
	BlockchainRef.Unlock()
	blockstring, _ := json.Marshal(block)
	reply.BlockString = string(blockstring)
	return nil
}

// TODO
// Get map of longest chain, with index of blockchain:hash
func (m InkMiner) getChain(args *shared.BlockArgs, reply *shared.BlockArgs) (err error) {
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// MAIN, LOCAL
////////////////////////////////////////////////////////////////////////////////

func decodePPKeys(encodedPriv string, encodedPub string) (privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) {
	// Decode strings to byte arrays
	decodedPriv, _ := hex.DecodeString(encodedPriv)
	decidedPub, _ := hex.DecodeString(encodedPub)

	// Parse x509
	privKey, _ = x509.ParseECPrivateKey(decodedPriv)
	parsedPubKey, _ := x509.ParsePKIXPublicKey(decidedPub)
	pubKey = parsedPubKey.(*ecdsa.PublicKey)

	return privKey, pubKey
}

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// Check for correct arguments
	args := os.Args
	if len(args) != 4 {
		fmt.Println("Usage: go run ink-miner.go [server ip:port] [pubKey] [privKey]")
		return
	}
	serverAddr := args[1]
	pubKeyString := args[2]
	privKeyString := args[3]

	fmt.Println("Here is the private key string: ", privKeyString)
	fmt.Println("Here is the public key string: ", pubKeyString)

	privKey, pubKey := decodePPKeys(privKeyString, pubKeyString)

	PubKey = *pubKey
	PrivKey = privKey
	inkMap = make(map[string]uint32)

	ConnectServer(serverAddr)

	// if sole miner, create blockchain; else request blockchain from other miners
	if len(connectedMiners.Miners) == 0 {
		BlockchainRef.Lock()
		BlockchainRef = NewBlockchain()
		BlockchainRef.Unlock()
	} else {
		//TODO do some shit to get the actual blocks
		// TODO ask for the missing blocks from
		getLongestChain()
	}
}
