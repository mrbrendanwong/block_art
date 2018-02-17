package shared

import (
	"crypto/ecdsa"
	"math/big"
)

// Represents a type of shape in the BlockArt system.
type ShapeType int

type ShapeOp struct {
	ShapeType      ShapeType
	ShapeSvgString string
	Fill           string
	Stroke         string
}

type AddShapeInfo struct {
	ValidateNum uint8
	InkRequired uint32
	ShapeOp     ShapeOp
}

type ShapeOpSig struct {
	R *big.Int
	S *big.Int
}

type Op struct {
	// ShapeOp is an application shape operation
	ShapeOp ShapeOp
	// ShapeOpSig is the signature of the shape operation generated using the private key and the operation
	ShapeOpSig ShapeOpSig
	// PubKeyArtNode is the public key of the artnode that generated the op
	PubKeyArtNode string
	// InkRequired is the amount of ink required for this op
	InkRequired uint32
	// ValidateNum
	ValidateNum uint8
}

type AddShapeResponse struct {
	ShapeHash    string
	BlockHash    string
	InkRemaining uint32
	Err          error
}

type BlockArgs struct {
	BlockString  string
	IndexHashMap map[int]string
}

type Message struct {
	PublicKey    ecdsa.PublicKey
	InkRemaining uint32
}
