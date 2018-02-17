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

	/*
	 *BEGIN OPERATIONS 
	 */

	// Keep on checking ink until we have a certain amount
	var inkAmount uint32
	for {
	   // Get ink
	   inkAmount, err = canvas.GetInk()
	   if checkError(err) != nil {
	   	   return
	   }
	   fmt.Println("Here is the amount of ink")
	   fmt.Printf("%d\n", int(inkAmount))

	   if int(inkAmount) > 1000 {
	   	   break
	   }
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