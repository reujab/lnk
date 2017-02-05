package lnk

import (
	"encoding/binary"
	"errors"
	"io"
)

// LNK represents the parsed information in a .lnk file.
type LNK struct {
	HeaderSize                  int32
	CLSID                       [16]byte
	LinkFlags                   int32
	HasTargetIDList             bool
	HasLinkInfo                 bool
	HasName                     bool
	HasRelativePath             bool
	HasWorkingDir               bool
	HasArguments                bool
	HasIconLocation             bool
	IsUnicode                   bool
	ForceNoLinkInfo             bool
	HasExpString                bool
	RunInSeperateProcess        bool
	HasDarwinID                 bool
	RunAsUser                   bool
	HasExpIcon                  bool
	NoPidlAlias                 bool
	RunWithShimLayer            bool
	ForceNoLinkTrack            bool
	EnableTargetMetadata        bool
	DisableLinkPathTracking     bool
	DisableKnownFolderTracking  bool
	DisableKnownFolderAlias     bool
	AllowLinkToLink             bool
	UnaliasOnSave               bool
	PreferEnvironmentPath       bool
	KeepLocalIDListForUNCTarget bool
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

	err = binary.Read(file, endianness, &lnk.LinkFlags)

	if err != nil {
		return
	}

	lnk.HasTargetIDList = lnk.LinkFlags&0x00000001 != 0
	lnk.HasLinkInfo = lnk.LinkFlags&0x00000002 != 0
	lnk.HasName = lnk.LinkFlags&0x00000004 != 0
	lnk.HasRelativePath = lnk.LinkFlags&0x00000008 != 0
	lnk.HasWorkingDir = lnk.LinkFlags&0x00000010 != 0
	lnk.HasArguments = lnk.LinkFlags&0x00000020 != 0
	lnk.HasIconLocation = lnk.LinkFlags&0x00000040 != 0
	lnk.IsUnicode = lnk.LinkFlags&0x00000080 != 0
	lnk.ForceNoLinkInfo = lnk.LinkFlags&0x00000100 != 0
	lnk.HasExpString = lnk.LinkFlags&0x00000200 != 0
	lnk.RunInSeperateProcess = lnk.LinkFlags&0x00000400 != 0
	// Unused1
	lnk.HasDarwinID = lnk.LinkFlags&0x00001000 != 0
	lnk.RunAsUser = lnk.LinkFlags&0x00002000 != 0
	lnk.HasExpIcon = lnk.LinkFlags&0x00004000 != 0
	lnk.NoPidlAlias = lnk.LinkFlags&0x00008000 != 0
	// Unused2
	lnk.RunWithShimLayer = lnk.LinkFlags&0x00020000 != 0
	lnk.ForceNoLinkTrack = lnk.LinkFlags&0x00040000 != 0
	lnk.EnableTargetMetadata = lnk.LinkFlags&0x00080000 != 0
	lnk.DisableLinkPathTracking = lnk.LinkFlags&0x00100000 != 0
	lnk.DisableKnownFolderTracking = lnk.LinkFlags&0x00200000 != 0
	lnk.DisableKnownFolderAlias = lnk.LinkFlags&0x00400000 != 0
	lnk.AllowLinkToLink = lnk.LinkFlags&0x00800000 != 0
	lnk.UnaliasOnSave = lnk.LinkFlags&0x01000000 != 0
	lnk.PreferEnvironmentPath = lnk.LinkFlags&0x02000000 != 0
	lnk.KeepLocalIDListForUNCTarget = lnk.LinkFlags&0x04000000 != 0

	return
}
