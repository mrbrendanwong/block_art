package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"./blockartlib"
)

func main() {
	// Set args
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	if len(os.Args) != 3 {
		fmt.Println("Usage: ", os.Args[0], "server")
		os.Exit(1)
	}

	minerAddr := os.Args[1]
	privKeyString := os.Args[2]

	privKey := decodePrivKey(privKeyString)

	// Open a canvas.
	canvas, _, err := blockartlib.OpenCanvas(minerAddr, *privKey)
	if checkError(err) != nil {
		return
	}

	validateNum := uint8(2)

	/*
	 *BEGIN OPERATIONS 
	 */

	// Get Genesis block
	genesisHash, err := canvas.GetGenesisBlock()
	if checkError(err) != nil {
		return
	}

	// Get ink
	inkAmount, err := canvas.GetInk()
	if checkError(err) != nil {
		return
	}
	fmt.Println("Here is the amount of ink")
	fmt.Printf("%d\n", int(inkAmount))

	// Draw line 1.
	shapeHash, blockHash, _, err := canvas.AddShape(validateNum, blockartlib.PATH, "M 0 0 L 0 5", "transparent", "red")
	if checkError(err) != nil {
		return
	}

	// Draw line 2.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 0 0 L 5 0", "transparent", "blue")
	if checkError(err) != nil {
		return
	}

	// Get SVG string of line 1
	svgString, err := canvas.GetSvgString(shapeHash)
	if checkError(err) != nil {
		return
	}

	fmt.Println("Here is the SVG string of our first shape hash")
	fmt.Println(svgString)

	// Get shapes for first blockhash
	line1ShapeHashes, err := canvas.GetShapes(blockHash)
	if checkError(err) != nil {
		return
	}

	fmt.Println("Here are the shape hashes our first block hash")
	for _, hash := range line1ShapeHashes {
		fmt.Println(hash)
	}

	// Delete the line.
	_, err = canvas.DeleteShape(validateNum, shapeHash)
	if checkError(err) != nil {
		return
	}

	// Get children of Genesis block
	childrenHashes, err := canvas.GetChildren(genesisHash)
	if checkError(err) != nil {
		return
	}

	fmt.Println("Here are the children hashses")
	for _, hash := range childrenHashes {
		fmt.Println(hash)
	}

	// Close the canvas.
	_, err = canvas.CloseCanvas()
	if checkError(err) != nil {
		return
	}
}

func decodePrivKey(encodedPriv string) (privKey *ecdsa.PrivateKey) {
	// Decode strings to byte arrays
	decodedPriv, _ := hex.DecodeString(encodedPriv)

	// Parse x509
	privKey, _ = x509.ParseECPrivateKey(decodedPriv)

	return privKey
}

// If error is non-nil, print it out and return it.
func checkError(err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error ", err.Error())
		return err
	}
	return nil
}