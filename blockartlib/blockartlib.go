/*

This package specifies the application's interface to the the BlockArt
library (blockartlib) to be used in project 1 of UBC CS 416 2017W2.

*/

package blockartlib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net/rpc"
	"os"
	"regexp"
	"strconv"
	"strings"

	"../shared"
)

const (
	// Path shape.
	PATH shared.ShapeType = iota

	// Circle shape (extra credit).
	// CIRCLE
)

var (
	Miner      *rpc.Client
	minerAddr  string
	publicKey  ecdsa.PublicKey
	privateKey ecdsa.PrivateKey
	errLog     *log.Logger = log.New(os.Stderr, "[artnode] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
)

const SVGSTRING_MAXLEN = 128
const BA_FILE = "blockArt.html"

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
	connected bool
}

type Coordinates struct {
	x int
	y int
}

var (
	initiated bool
	Settings  CanvasSettings
)

// This function determines how much ink is needed to draw given shape
func getInkRequired(shape shared.ShapeOp) (inkNeeded uint32, err error) {

	points, err := getVertices(shape.ShapeSvgString)
	if err != nil {
		// Out of bounds
		return 0, OutOfBoundsError{}
	}
	var ink float64 = 0
	j := 0
	if shape.Stroke != "transparent" {
		// Find parameter
		for j < len(points)-1 {
			x_dist := math.Abs(float64(points[j+1].x - points[j].x))
			y_dist := math.Abs(float64(points[j+1].y - points[j].y))
			ink = ink + math.Sqrt(math.Pow(x_dist, 2)+math.Pow(y_dist, 2))
			j++
		}
	}

	if shape.Fill != "transparent" {
		// Find Area
		// https://www.mathopenref.com/coordpolygonarea.html
		for j < len(points)-1 {
			ink = ink + float64(points[j].x*points[j+1].y-points[j].y*points[j+1].x)
			j++
		}
		ink = ink / 2
	}

	return uint32(ink), nil
}

// Add shape to canvas
func (a ArtNode) AddShape(validateNum uint8, shapeType shared.ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error) {
	if !a.connected {
		return "", "", 0, DisconnectedError("")
	}

	// Return StringTooLongError if string longer than 128 bytes
	if len(shapeSvgString) > SVGSTRING_MAXLEN {
		return "", "", 0, ShapeSvgStringTooLongError("")
	}

	shapeOp := &shared.ShapeOp{
		ShapeType:      shapeType,
		ShapeSvgString: shapeSvgString,
		Fill:           fill,
		Stroke:         stroke,
	}

	InkRequired, err := getInkRequired(*shapeOp)
	if err != nil {
		handleError("Error getting ink required.", err)
		return "", "", 0, err
	}
	InkRemaining, err := a.GetInk()

	if InkRequired > InkRemaining {
		return "", "", 0, InsufficientInkError(InkRequired)
	}

	// Sign the shape op
	r, s, _ := ecdsa.Sign(rand.Reader, &privateKey, []byte(shapeOp.ShapeSvgString))
	shapeOpSig := &shared.ShapeOpSig{
		R: r,
		S: s,
	}
	if err != nil {
		fmt.Println()
	}
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	encodedBytes := hex.EncodeToString(pubKeyBytes)
	op := &shared.Op{
		ShapeOpSig:    *shapeOpSig,
		ValidateNum:   validateNum,
		InkRequired:   InkRequired,
		ShapeOp:       *shapeOp,
		PubKeyArtNode: encodedBytes,
	}
	addShapeResponse := shared.AddShapeResponse{}

	error := Miner.Call("InkMiner.AddShape", op, &addShapeResponse)
	if error != nil {
		fmt.Println(error)
	}
	fmt.Println("returned from call")

	// TODO fix error handling
	if addShapeResponse.Err != nil {
		return "", "", 0, addShapeResponse.Err
	}

	fmt.Printf("InkRemaining after drawing shape:%d\n", addShapeResponse.InkRemaining)

	return "", "", addShapeResponse.InkRemaining, nil
}

func (a ArtNode) GetSvgString(shapeHash string) (svgString string, err error) {
	if !a.connected {
		return "", DisconnectedError("")
	}

	var shape shared.ShapeOp
	err = a.Miner.Call("InkMiner.GetShape", shapeHash, &shape)
	if err != nil {
		handleError("Could not retrieve svg string.", err)
		return "", err
	}

	svgString = "<path d=\"" + shape.ShapeSvgString + "\" fill=\"" + shape.Fill + "\" stroke=\"" + shape.Stroke + "\"/>\n"

	return svgString, nil
}

func (a ArtNode) GetInk() (inkRemaining uint32, err error) {
	message := shared.Message{
		PublicKey: publicKey,
	}
	reply := shared.Message{}
	error := Miner.Call("InkMiner.GetInk", message, &reply)
	if error != nil {
		return 0, DisconnectedError("Could not get ink")
	}
	fmt.Printf("Ink from ink-miner:%d\n", reply.InkRemaining)

	return reply.InkRemaining, nil
}

func (a ArtNode) DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error) {
	//	if !a.connected {
	//		return 0, DisconnectedError("")
	//	}
	//
	//	var shape shared.Shape
	//	var newShape shared.Shape
	//	// Get shape from block chain
	//	err = a.Miner.Call("InkMiner.GetShape", shapeHash, &shape)
	//	if err != nil {
	//		handleError("Could not delete shape.", err)
	//		return 0, err
	//	}
	//	if shape.Fill != "transparent"{
	//		// Create new shape
	//		newShape = shared.Shape{
	//			shape.ShapeType,
	//			shape.ShapeSvgString,
	//			"white",
	//			"white",
	//		}
	//	} else {
	//		// Create new shape
	//		newShape = shared.Shape{
	//			shape.ShapeType,
	//			shape.ShapeSvgString,
	//			shape.Fill,
	//			shape.Stroke,
	//		}
	//	}
	//
	//	// Sign the shape op
	//	r, s, _ := ecdsa.Sign(rand.Reader, &privateKey, []byte(shapeOp.ShapeSvgString))
	//	shapeOpSig := &shared.ShapeOpSig{
	//		R: r,
	//		S: s,
	//	}
	//	if err != nil {
	//		fmt.Println()
	//	}
	//	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	//	encodedBytes := hex.EncodeToString(pubKeyBytes)
	//
	//	// Create new shape op
	//	op := &shared.Op{
	//		ShapeOpSig:    *shapeOpSig,
	//		ValidateNum:   validateNum,
	//		InkRequired:   0,
	//		ShapeOp:       newShape,
	//		PubKeyArtNode: encodedBytes,
	//	}
	//
	//	var response shared.AddShapeResponse
	//	err = a.Miner.Call("InkMiner.AddShape", op, &response)
	//
	//	// TODO fix error handling
	//	if response.Err != nil {
	//		return 0, response.Err
	//	}
	//
	//	fmt.Printf("InkRemaining after drawing shape:%d\n", response.InkRemaining)
	//
	//	return response.InkRemaining, nil
	return 0, nil
}

func (a ArtNode) GetShapes(blockHash string) (shapeHashes []string, err error) {
	if !a.connected {
		return nil, DisconnectedError("")
	}
	err = a.Miner.Call("InkMiner.GetShapes", blockHash, &shapeHashes)
	if err != nil {
		handleError("Could not find block ", err)
		return nil, InvalidBlockHashError(blockHash)
	}
	return shapeHashes, nil
}

// Get hash of the first block of the block chain
func (a ArtNode) GetGenesisBlock() (blockHash string, err error) {
	if !a.connected {
		return "", DisconnectedError("")
	}
	err = a.Miner.Call("InkMiner.GetGenesisBlock", "", &blockHash)
	if err != nil {
		handleError("Error getting genesis block", err)
		return "", err
	}
	return blockHash, nil
}

func (a ArtNode) GetChildren(blockHash string) (blockHashes []string, err error) {
	if !a.connected {
		return nil, DisconnectedError("")
	}

	err = a.Miner.Call("InkMiner.GetChildren", blockHash, &blockHashes)
	if err != nil {
		handleError("Error getting children", err)
		return nil, err
	}
	return blockHashes, nil
}

// Close connection between art node and canvas
func (a ArtNode) CloseCanvas() (inkRemaining uint32, err error) {
	if !a.connected {
		return 0, DisconnectedError("")
	}
	// Get inkRemaining from miner
	inkRemaining, err = a.GetInk()

	var allShapes []string
	var allSvgStrings []string

	genesisBlock, err := a.GetGenesisBlock()
	allBlocks, err := a.GetChildren(genesisBlock) // returns hashes of all children
	for _, blockHash := range allBlocks {
		shapes, _ := a.GetShapes(blockHash)
		for _, shape := range shapes {
			allShapes = append(allShapes, shape)
		}
	}

	for _, shapeHash := range allShapes {
		svgString, _ := a.GetSvgString(shapeHash)
		allSvgStrings = append(allSvgStrings, svgString)
	}

	drawCanvas(allSvgStrings)

	// Close connection to miner
	a.Miner.Close()
	a.connected = false // Mark as no longer connected

	return 0, nil // Return no ink remaining for now
}

//// This function draws the canvas to a HTML file
func drawCanvas(allStrings []string) (err error) {
	//Create and write to HTML file
	file, err := os.OpenFile(BA_FILE, os.O_CREATE|os.O_WRONLY, 0664)
	file.Write([]byte("<svg height=\"" + strconv.Itoa(int(Settings.CanvasXMax)) + "\" width=\"" + strconv.Itoa(int(Settings.CanvasYMax)) + "\">\n</svg>"))
	for _, str := range allStrings {
		file.Write([]byte(str))
	}
	file.Write([]byte("</svg>"))
	file.Close()
	fmt.Println("Canvas can be seen at ", BA_FILE)
	return nil
}

// This function returns the list of vertices contained in the SVG string
func getVertices(shapeSVGString string) (vertices []Coordinates, err error) {
	// https://www.w3.org/TR/SVG2/paths.html
	// ex. M 0 0 L 0 5

	points := []Coordinates{}
	r, err := regexp.Compile(`[MmHhVvLlZz][ \-0-9]*`)
	if err != nil {
		fmt.Println("Error getting vertices.", err)
		return nil, err
	}
	res := r.FindAllString(shapeSVGString, -1)

	var x_start, y_start, x_current, y_current float64
	for i := range res {
		var tmp int64
		args := strings.Fields(res[i])
		if args[0] == "M" {
			// Move to location given
			tmp, _ = strconv.ParseInt(args[1], 0, 8)
			x_start = float64(tmp)
			x_current = x_start
			tmp, _ = strconv.ParseInt(args[2], 0, 8)
			y_start = float64(tmp)
			y_current = y_start

		} else if args[0] == "L" {
			// Draw line from start pos to given pos
			tmp, _ = strconv.ParseInt(args[1], 0, 8)
			x_current = math.Abs(float64(tmp))
			tmp, _ = strconv.ParseInt(args[2], 0, 8)
			y_current = math.Abs(float64(tmp))

		} else if args[0] == "l" {
			// Draw line from current pos to given pos
			tmp, _ = strconv.ParseInt(args[1], 0, 8)
			x_current = math.Abs(float64(tmp) + x_current)
			tmp, _ = strconv.ParseInt(args[2], 0, 8)
			y_current = math.Abs(float64(tmp) + y_current)

		} else if args[0] == "H" {
			// Draw horizontal line from start pos to given pos
			tmp, _ := strconv.ParseInt(args[1], 0, 8)

			x_current = math.Abs(float64(tmp))

		} else if args[0] == "h" {
			// Draw horizontal line from current pos to given pos
			tmp, _ = strconv.ParseInt(args[1], 0, 8)
			x_current = math.Abs(float64(tmp) + x_current)

		} else if args[0] == "V" {
			// Draw vertical line from start pos to given pos
			tmp, _ = strconv.ParseInt(args[1], 0, 8)

			y_current = math.Abs(float64(tmp))

		} else if args[0] == "v" {
			// Draw vertical line from current pos to given pos
			tmp, _ = strconv.ParseInt(args[1], 0, 8)
			y_current = math.Abs(float64(tmp) + y_current)

		} else if args[0] == "Z" || args[0] == "z" {
			// Return to start pos
			x_current = x_start
			y_current = y_start
		}

		// Check that vertices are not out of bounds
		if x_current < 0 || x_current > float64(Settings.CanvasXMax) {
			return nil, OutOfBoundsError{}
		}
		if y_current < 0 || y_current > float64(Settings.CanvasYMax) {
			return nil, OutOfBoundsError{}
		}
		points = append(points, Coordinates{int(x_current), int(y_current)})
	}
	return points, nil
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
		fmt.Println("Could not open Canvas.", DisconnectedError(""))
		return nil, CanvasSettings{}, DisconnectedError("")
	}

	// Save key
	publicKey = privKey.PublicKey
	privateKey = privKey

	// Create art node
	canvas = &ArtNode{minerAddr, miner, true}
	Miner = miner
	// Register art node on miner
	// Get CanvasSettings from miner
	var settings CanvasSettings
	err = Miner.Call("InkMiner.RegisterArtNode", privKey.PublicKey, &settings)
	if err != nil {
		// Public Key does not match
		handleError("Public key does not match.", err)
		return nil, CanvasSettings{}, err
	}
	Settings = settings
	// For now return DisconnectedError
	return canvas, settings, nil
}

func handleError(msg string, e error) {
	if e != nil {
		errLog.Println(msg, e.Error())
	}
}
