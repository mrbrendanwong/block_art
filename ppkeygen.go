/*
 * This program willgenerate a unique public and private key pair randomly as a pair of strings
 * 
 */

 package main

 import (
 	"fmt"
 	"os"
 	"reflect"

 	"crypto/ecdsa"
 	"crypto/elliptic"
 	"crypto/x509"
 	"crypto/rand"
 	"encoding/hex"
 )

 func genPPKeyPair() (encodedPriv, encodedPub string) {
 	// Seed for key generation
 	r := rand.Reader

 	// Generate key
 	privKey, err := ecdsa.GenerateKey(elliptic.P384(), r)
 	checkError(err)
 	pubKey := &privKey.PublicKey

 	// Format keys
 	formattedPrivKey, err := x509.MarshalECPrivateKey(privKey)
 	checkError(err)
 	formattedPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
 	checkError(err)

 	// Encode keys to string
 	encodedPriv = hex.EncodeToString(formattedPrivKey)
 	encodedPub = hex.EncodeToString(formattedPubKey)

 	a1, a2 := decodePPKeys(encodedPriv, encodedPub)

 	if !reflect.DeepEqual(privKey, a1) {
 		fmt.Println("Private keys do not match.")
 	}

 	 if !reflect.DeepEqual(pubKey, a2) {
 		fmt.Println("Private keys do not match.")
 	}

 	return encodedPriv, encodedPub
 }

func decodePPKeys(encodedPriv string, encodedPub string) (privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey){
	// Decode strings to byte arrays
	decodedPriv, _ := hex.DecodeString(encodedPriv)
	decodedPub, _ := hex.DecodeString(encodedPub)

	// Parse x509
	privKey, err := x509.ParseECPrivateKey(decodedPriv)
	if err != nil {
		fmt.Println("Something went wrong parsing the private key!: ", err)
	}
	parsedPubKey, err := x509.ParsePKIXPublicKey(decodedPub)
	if err != nil {
		fmt.Println("Something went wrong parsing the public key!: ", err)
	}
	pubKey = parsedPubKey.(*ecdsa.PublicKey)

	return privKey, pubKey
}

 func writeKeyFiles(privKey string, pubKey string){
 	// Private key
 	fname := "privkey"
 	f, err := os.Create(fname)
 	checkError(err)
 	
 	_, err = f.Write([]byte(privKey))
 	checkError(err)
 	fmt.Printf("Wrote private key to %s\n", fname)
 	f.Close()

 	// Public key
 	fname = "pubkey"
 	f, err = os.Create(fname)
 	checkError(err)

 	_, err = f.Write([]byte(pubKey))
 	checkError(err)
 	fmt.Printf("Wrote public key to %s\n", fname)
 	f.Close()
 }
 
 func main() {
 	privKey, pubKey := genPPKeyPair()

 	fmt.Println("Private key: ", privKey)
 	fmt.Println("Public key: ", pubKey)

 	writeKeyFiles(privKey, pubKey)
 }

// General error checking
func checkError(err error) {
	if err != nil {
		fmt.Println("Something bad happened: ", err.Error())
		os.Exit(1)
	}
}