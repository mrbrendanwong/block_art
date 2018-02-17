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

	// Try to draw intersecting cross. Second shape should fail.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 0 50 H 100", "transparent", "red")
	if checkError(err) != nil {
		return
	}

	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 50 100 V 0", "transparent", "blue")
	if checkError(err) != nil {
		return
	}

	// Try to draw a square, and a square beside it on same border.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 0 250 H 100 V 350 h -100 Z", "fill", "blue")
	if checkError(err) != nil {
		return
	}

	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 200 250 V 350 H 100 v -100 Z", "fill", "red")
	if checkError(err) != nil {
		return
	}

	// Try to draw a line, then draw a line trying to go to where it ended
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 250 50 H 350", "transparent", "red")
	if checkError(err) != nil {
		return
	}

	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 350 50 H 200", "transparent", "blue")
	if checkError(err) != nil {
		return
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