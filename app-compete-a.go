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
	"time"

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

	// Draw line 1.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 500 750 h 100 0", "transparent", "red")
	if checkError(err) != nil {
		return
	}

	time.Sleep(10 * time.Second)

	// Draw line 2.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 650 750 h 100 0", "transparent", "blue")
	if checkError(err) != nil {
		return
	}

	time.Sleep(25 * time.Second)

	// Draw line 3.
	_, _, _, err = canvas.AddShape(validateNum, blockartlib.PATH, "M 800 750 h 100", "transparent", "red")
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