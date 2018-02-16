/*

This package specifies the application's interface to the the BlockArt
library (blockartlib) to be used in project 1 of UBC CS 416 2017W2.

*/

package blockartlib

import "crypto/ecdsa"
import "../shared"
import (
	"fmt"
	"math"
	"net/rpc"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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

type CanvasInstance struct {
	sync.RWMutex
	canvas [][]bool
	file   *os.File
}

type Coordinates struct {
	x int
	y int
}

var (
	initiated bool
	BACanvas  *CanvasInstance
	Settings  CanvasSettings
)

// This function determines how much ink is needed to draw given shape
func getInkRequired(shape shared.Shape) (inkNeeded uint32, err error) {

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

func (a ArtNode) AddShape(validateNum uint8, shapeType shared.ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error) {
	if !a.connected {
		return "", "", 0, DisconnectedError("")
	}

	// Return StringTooLongError if string longer than 128 bytes
	if len(shapeSvgString) > SVGSTRING_MAXLEN {
		return "", "", 0, ShapeSvgStringTooLongError("")
	}

	shape := &shared.Shape{
		ShapeType:      shapeType,
		ShapeSvgString: shapeSvgString,
		Fill:           fill,
		Stroke:         stroke,
	}

	InkRequired, err := getInkRequired(*shape)
	if err != nil {
		fmt.Println("Error getting ink required.")
		return "", "", 0, err
	}
	InkRemaining, err := a.GetInk()

	if InkRequired > InkRemaining {
		return "", "", 0, InsufficientInkError(InkRequired)
	}

	// Check that shape does not overlap any existing shape
	isValid := isValidShape(*shape)
	if !isValid {
		return "", "", 0, InvalidShapeSvgStringError("")
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

	drawShape(shapeSvgString, fill, stroke) // draw onto HTML file

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
	if !a.connected {
		return 0, DisconnectedError("")
	}
	// TODO:
	// Get inkRemaining from miner

	// TODO:
	// only close if last connected miner
	BACanvas.file.Close()

	// Close connection to miner
	a.Miner.Close()
	a.connected = false // Mark as no longer connected

	return 0, nil // Return no ink remaining for now
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

// This function checks that the given shape does not overlap any existing shapes
func isValidShape(shape shared.Shape) (valid bool) {
	// TODO:
	// NO SUCH THING AS AN OVERLAP FOR NOW
	return true
}

// This function draws the given shape to HTML file
func drawShape(shapeSvgString string, fill string, stroke string) {
	f := BACanvas.file
	ptr, err := f.Seek(-int64(len("</svg>")), 2)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	f.WriteAt([]byte("<path d=\""+shapeSvgString+"\" fill=\""+fill+"\" stroke=\""+stroke+"\"/>\n</svg>"), ptr)
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
	canvas = &ArtNode{minerAddr, miner, true}
	Miner = miner
	// Register art node on miner
	// Get CanvasSettings from miner
	var settings CanvasSettings
	err = Miner.Call("InkMiner.RegisterArtNode", privKey.PublicKey, &settings)
	if err != nil {
		// Public Key does not match
		return nil, CanvasSettings{}, err
	}
	Settings = settings

	// create canvas if not yet created
	if !initiated {
		createCanvas(int(settings.CanvasXMax), int(settings.CanvasYMax))
	}
	// For now return DisconnectedError
	return canvas, settings, nil
}

func createCanvas(x int, y int) {
	grid := make([][]bool, y)
	for i := 0; i < y; i++ {
		grid[i] = make([]bool, x)
	}

	file, err := os.OpenFile(BA_FILE+"_"+time.Now().String(), os.O_CREATE|os.O_WRONLY, 0664)
	file.Write([]byte("<svg height=\"" + strconv.Itoa(x) + "\" width=\"" + strconv.Itoa(y) + "\">\n</svg>"))
	//defer file.Close()
	if err != nil {
		fmt.Println("Error: could not create HTML file.")
	}

	BACanvas = &CanvasInstance{canvas: grid, file: file}
}
