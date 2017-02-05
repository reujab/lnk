package lnk

import (
	"encoding/binary"
	"errors"
	"io"
)

// LNK represents the parsed information in a .lnk file.
type LNK struct {
	HeaderSize int32
	CLSID      [16]byte
}

// ErrInvalidHeaderSize is returned when the header size is not 76.
var ErrInvalidHeaderSize = errors.New("invalid header size")

// ErrInvalidCLSID is returned when the CLSID is not valid
var ErrInvalidCLSID = errors.New("invalid CLSID")

var endianness = binary.LittleEndian
var validCLSID = [...]byte{
	1, 20, 2, 0, 0, 0, 0, 0,
	192, 0, 0, 0, 0, 0, 0, 70,
}

// Parse parses an io.Reader into a LNK.
func Parse(file io.Reader) (lnk *LNK, err error) {
	lnk = new(LNK)
	err = binary.Read(file, endianness, &lnk.HeaderSize)

	if err != nil {
		return
	}

	if lnk.HeaderSize != 76 {
		return lnk, ErrInvalidHeaderSize
	}

	_, err = file.Read(lnk.CLSID[:])

	if err != nil {
		return
	}

	if lnk.CLSID != validCLSID {
		return lnk, ErrInvalidCLSID
	}

	return
}
