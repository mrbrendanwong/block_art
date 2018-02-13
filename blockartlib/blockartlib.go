/*

This package specifies the application's interface to the the BlockArt
library (blockartlib) to be used in project 1 of UBC CS 416 2017W2.

*/

package blockartlib

import "crypto/ecdsa"
import "../shared"
import (
	"fmt"
	"net/rpc"
	"os"
	"sync"
)

const (
	// Path shape.
	PATH shared.ShapeType = iota

	// Circle shape (extra credit).
	// CIRCLE
)

var (
	Miner     *rpc.Client
	minerAddr string
)

// Settings for a canvas in BlockArt.
type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32
	CanvasYMax uint32
}

// Settings for an instance of the BlockArt project/network.
type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string

	// The minimum number of ink miners that an ink miner should be
	// connected to. If the ink miner dips below this number, then
	// they have to retrieve more nodes from the server using
	// GetNodes().
	MinNumMinerConnections uint8

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32
	InkPerNoOpBlock uint32

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8
	PoWDifficultyNoOpBlock uint8

	// Canvas settings
	CanvasSettings CanvasSettings
}

////////////////////////////////////////////////////////////////////////////////////////////
// <ERROR DEFINITIONS>

// These type definitions allow the application to explicitly check
// for the kind of error that occurred. Each API call below lists the
// errors that it is allowed to raise.
//
// Also see:
// https://blog.golang.org/error-handling-and-go
// https://blog.golang.org/errors-are-values

// Contains address IP:port that art node cannot connect to.
type DisconnectedError string

func (e DisconnectedError) Error() string {
	return fmt.Sprintf("BlockArt: cannot connect to [%s]", string(e))
}

// Contains amount of ink remaining.
type InsufficientInkError uint32

func (e InsufficientInkError) Error() string {
	return fmt.Sprintf("BlockArt: Not enough ink to addShape [%d]", uint32(e))
}

// Contains the offending svg string.
type InvalidShapeSvgStringError string

func (e InvalidShapeSvgStringError) Error() string {
	return fmt.Sprintf("BlockArt: Bad shape svg string [%s]", string(e))
}

// Contains the offending svg string.
type ShapeSvgStringTooLongError string

func (e ShapeSvgStringTooLongError) Error() string {
	return fmt.Sprintf("BlockArt: Shape svg string too long [%s]", string(e))
}

// Contains the bad shape hash string.
type InvalidShapeHashError string

func (e InvalidShapeHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid shape hash [%s]", string(e))
}

// Contains the bad shape hash string.
type ShapeOwnerError string

func (e ShapeOwnerError) Error() string {
	return fmt.Sprintf("BlockArt: Shape owned by someone else [%s]", string(e))
}

// Empty
type OutOfBoundsError struct{}

func (e OutOfBoundsError) Error() string {
	return fmt.Sprintf("BlockArt: Shape is outside the bounds of the canvas")
}

// Contains the hash of the shape that this shape overlaps with.
type ShapeOverlapError string

func (e ShapeOverlapError) Error() string {
	return fmt.Sprintf("BlockArt: Shape overlaps with a previously added shape [%s]", string(e))
}

// Contains the invalid block hash.
type InvalidBlockHashError string

func (e InvalidBlockHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid block hash [%s]", string(e))
}

// </ERROR DEFINITIONS>
////////////////////////////////////////////////////////////////////////////////////////////

// Represents a canvas in the system.
type Canvas interface {
	// Adds a new shape to the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - InsufficientInkError
	// - InvalidShapeSvgStringError
	// - ShapeSvgStringTooLongError
	// - ShapeOverlapError
	// - OutOfBoundsError
	AddShape(validateNum uint8, shapeType shared.ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error)

	// Returns the encoding of the shape as an svg string.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidShapeHashError
	GetSvgString(shapeHash string) (svgString string, err error)

	// Returns the amount of ink currently available.
	// Can return the following errors:
	// - DisconnectedError
	GetInk() (inkRemaining uint32, err error)

	// Removes a shape from the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - ShapeOwnerError
	DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error)

	// Retrieves hashes contained by a specific block.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetShapes(blockHash string) (shapeHashes []string, err error)

	// Returns the block hash of the genesis block.
	// Can return the following errors:
	// - DisconnectedError
	GetGenesisBlock() (blockHash string, err error)

	// Retrieves the children blocks of the block identified by blockHash.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetChildren(blockHash string) (blockHashes []string, err error)

	// Closes the canvas/connection to the BlockArt network.
	// - DisconnectedError
	CloseCanvas() (inkRemaining uint32, err error)
}

type ArtNode struct {
	minerAddr string
	Miner     *rpc.Client
}

type CanvasInstance struct {
	sync.RWMutex
	canvas [][]bool
	file   *os.File
}

var (
	initiated bool
	BACanvas  *CanvasInstance
)

// TODO Calculate ink required for shape
func getInkRequired(shape shared.Shape) uint32 {
	return 5
}

func (a ArtNode) AddShape(validateNum uint8, shapeType shared.ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error) {
	shape := &shared.Shape{
		ShapeType:      shapeType,
		ShapeSvgString: shapeSvgString,
		Fill:           fill,
		Stroke:         stroke,
	}
	InkRequired := getInkRequired(*shape)
	InkRemaining, err := a.GetInk()
	if err != nil {
		return "", "", 0, err
	}
	if InkRequired > InkRemaining {
		return "", "", 0, InsufficientInkError(InkRequired)
	}

	addShapeInfo := &shared.AddShapeInfo{
		ValidateNum: validateNum,
		InkRequired: InkRequired,
		Shape:       *shape,
	}
	addShapeResponse := shared.AddShapeResponse{}

	Miner.Call("InkMiner.AddShape", addShapeInfo, &addShapeResponse)

	if addShapeResponse.Err != nil {
		return "", "", 0, addShapeResponse.Err
	}

	fmt.Printf("InkRemaining after drawing shape:%d\n", addShapeResponse.InkRemaining)

	return "", "", addShapeResponse.InkRemaining, nil
}

func (a ArtNode) GetSvgString(shapeHash string) (svgString string, err error) {
	return "", nil
}

func (a ArtNode) GetInk() (inkRemaining uint32, err error) {

	reply := shared.Reply{}
	error := Miner.Call("InkMiner.GetInk", reply, &reply)
	if error != nil {
		return 0, DisconnectedError("Could not get ink")
	}
	fmt.Printf("Ink from ink-miner:%d\n", reply.InkRemaining)

	return reply.InkRemaining, nil
}

func (a ArtNode) DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error) {
	return 0, nil
}

func (a ArtNode) GetShapes(blockHash string) (shapeHashes []string, err error) {
	return nil, nil
}

func (a ArtNode) GetGenesisBlock() (blockHash string, err error) {
	return "", nil
}

func (a ArtNode) GetChildren(blockHash string) (blockHashes []string, err error) {
	return nil, nil
}

func (a ArtNode) CloseCanvas() (inkRemaining uint32, err error) {
	fmt.Println("Closing canvas..")
	// TODO:
	// Get inkRemaining from miner

	// Unmount art ngitode from miner

	// Close connection to miner
	a.Miner.Close()

	return 0, nil // Return no ink remaining for now
}

// The constructor for a new Canvas object instance. Takes the miner's
// IP:port address string and a public-private key pair (ecdsa private
// key type contains the public key). Returns a Canvas instance that
// can be used for all future interactions with blockartlib.
//
// The returned Canvas instance is a singleton: an application is
// expected to interact with just one Canvas instance at a time.
//
// Can return the following errors:
// - DisconnectedError
func OpenCanvas(minerAddr string, privKey ecdsa.PrivateKey) (canvas Canvas, setting CanvasSettings, err error) {
	// Connect art node to miner
	miner, err := rpc.Dial("tcp", minerAddr)
	if err != nil {
		return nil, CanvasSettings{}, DisconnectedError("Could not open Canvas")
	}

	// Create art node
	canvas = &ArtNode{minerAddr, miner}
	Miner = miner
	// Register art node on miner
	// Get CanvasSettings from miner
	var settings CanvasSettings
	err = Miner.Call("InkMiner.RegisterArtNode", privKey.PublicKey, &settings)
	if err != nil {
		// Public Key does not match
		return nil, CanvasSettings{}, err
	}
	// create canvas if not yet created
	if !initiated {
		createCanvas(int(settings.CanvasXMax), int(settings.CanvasYMax))
	}
	// For now return DisconnectedError
	return canvas, settings, nil
}

func createCanvas(x int, y int) {
	fmt.Println("Creating canvas...")
	grid := make([][]bool, y)
	for i := 0; i < y; i++ {
		grid[i] = make([]bool, x)
	}

	file, err := os.Create("/tmp/blockArt.html")
	if err != nil {
		fmt.Println("Error: could not create HTML file.")
	}

	BACanvas = &CanvasInstance{canvas: grid, file: file}
}
