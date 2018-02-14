package shared

// Represents a type of shape in the BlockArt system.
type ShapeType int

type Shape struct {
	ShapeType      ShapeType
	ShapeSvgString string
	Fill           string
	Stroke         string
}

type AddShapeInfo struct {
	ValidateNum uint8
	InkRequired uint32
	Shape       Shape
}

type AddShapeResponse struct {
	ShapeHash    string
	BlockHash    string
	InkRemaining uint32
	Err          error
}

type Reply struct {
	InkRemaining uint32
}
