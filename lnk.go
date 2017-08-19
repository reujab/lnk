package lnk

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	// ShowNormal is the value of LNK.ShowCommand when the application should be
	// opened normally.
	ShowNormal = 1

	// ShowMaximized is the value of LNK.ShowCommand when the application should be
	// opened maximized.
	ShowMaximized = 3

	// ShowMinNoActive is the value of LNK.ShowCommand when the application should
	// be opened minimized.
	ShowMinNoActive = 7
)

// LNK represents the parsed information in a .lnk file.
// See https://msdn.microsoft.com/en-us/library/dd891314.aspx and https://github.com/libyal/liblnk/blob/15ec0a6ea940e79048ceee71861546485c4ab6d8/documentation/Windows%20Shortcut%20File%20%28LNK%29%20format.asciidoc#21-data-flags.
type LNK struct {
	// ShellLinkHeader
	LinkFlags                   uint32
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
	FileAttributes              uint32
	FileAttribute               struct {
		ReadOnly          bool
		Hidden            bool
		System            bool
		Directory         bool
		Archive           bool
		Normal            bool
		Temporary         bool
		SparseFile        bool
		ReparsePoint      bool
		Compressed        bool
		Offline           bool
		NotContentIndexed bool
		Encrypted         bool
	}
	CreationTime time.Time
	AccessTime   time.Time
	WriteTime    time.Time
	FileSize     uint32
	IconIndex    int32
	// If ShowCommand does not equal ShowNormal, ShowMaximized, or
	// ShowMinNoActive, ShowCommand must be treated as ShowNormal.
	ShowCommand    uint32
	HotKeyLowByte  byte
	HotKeyHighByte byte
	HotKey         struct {
		Key   string
		Shift bool
		Ctrl  bool
		Alt   bool
	}
	// LinkTargetIDList
	IDListSize  uint16
	IDListBytes []byte
	// LinkInfo
	LinkInfoSize                           uint32
	LinkInfoHeaderSize                     uint32
	LinkInfoFlags                          uint32
	VolumeIDAndLocalBasePath               bool
	CommonNetworkRelativeLinkAndPathSuffix bool
	VolumeIDOffset                         uint32
	LocalBasePathOffset                    uint32
	CommonNetworkRelativeLinkOffset        uint32
	CommonPathSuffixOffset                 uint32
	LocalBasePathOffsetUnicode             uint32
	CommonPathSuffixOffsetUnicode          uint32
	VolumeIDSize                           uint32
	DriveType                              uint32
	DriveSerialNumber                      uint32
	VolumeLabelOffset                      uint32
	VolumeLabelOffsetUnicode               uint32
	VolumeLabel                            string
	LocalBasePath                          string
}

var (
	// ErrInvalidHeaderSize is returned when the header size is not 76.
	ErrInvalidHeaderSize = errors.New("invalid header size")

	// ErrInvalidCLSID is returned when the CLSID is not valid
	ErrInvalidCLSID = errors.New("invalid CLSID")

	// ErrReservedBitSet is returned when a reserved bit is set
	ErrReservedBitSet = errors.New("reserved bit set")

	// ErrInvalidHotKey is returned when the hotkey low byte is invalid
	ErrInvalidHotKey = errors.New("invalid hotkey")
)

var endianness = binary.LittleEndian

var validCLSID = [16]byte{
	1, 20, 2, 0, 0, 0, 0, 0,
	192, 0, 0, 0, 0, 0, 0, 70,
}

// Parse parses an io.Reader into a LNK.
func Parse(file io.Reader) (*LNK, error) {
	reader := bufio.NewReader(file)
	lnk := new(LNK)

	var headerSize uint32
	err := binary.Read(file, endianness, &headerSize)
	if err != nil {
		return lnk, err
	}
	if headerSize != 76 {
		return lnk, ErrInvalidHeaderSize
	}

	var clsid [16]byte
	_, err = file.Read(clsid[:])
	if err != nil {
		return lnk, err
	}
	if clsid != validCLSID {
		return lnk, ErrInvalidCLSID
	}

	err = binary.Read(file, endianness, &lnk.LinkFlags)
	if err != nil {
		return lnk, err
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

	err = binary.Read(file, endianness, &lnk.FileAttributes)
	if err != nil {
		return lnk, err
	}
	lnk.FileAttribute.ReadOnly = lnk.FileAttributes&0x00000001 != 0
	lnk.FileAttribute.Hidden = lnk.FileAttributes&0x00000002 != 0
	lnk.FileAttribute.System = lnk.FileAttributes&0x00000004 != 0
	// Reserved1
	lnk.FileAttribute.Directory = lnk.FileAttributes&0x00000010 != 0
	lnk.FileAttribute.Archive = lnk.FileAttributes&0x00000020 != 0
	// Reserved2
	lnk.FileAttribute.Normal = lnk.FileAttributes&0x00000080 != 0
	lnk.FileAttribute.Temporary = lnk.FileAttributes&0x00000100 != 0
	lnk.FileAttribute.SparseFile = lnk.FileAttributes&0x00000200 != 0
	lnk.FileAttribute.ReparsePoint = lnk.FileAttributes&0x00000400 != 0
	lnk.FileAttribute.Compressed = lnk.FileAttributes&0x00000800 != 0
	lnk.FileAttribute.Offline = lnk.FileAttributes&0x00001000 != 0
	lnk.FileAttribute.NotContentIndexed = lnk.FileAttributes&0x00002000 != 0
	lnk.FileAttribute.Encrypted = lnk.FileAttributes&0x00004000 != 0
	if lnk.FileAttributes&0x00000008 != 0 || lnk.FileAttributes&0x00000040 != 0 {
		return lnk, ErrReservedBitSet
	}

	var creationTime uint64
	err = binary.Read(file, endianness, &creationTime)
	if err != nil {
		return lnk, err
	}
	lnk.CreationTime = windowsNanoToTime(creationTime)

	var accessTime uint64
	err = binary.Read(file, endianness, &accessTime)
	if err != nil {
		return lnk, err
	}
	lnk.AccessTime = windowsNanoToTime(accessTime)

	var writeTime uint64
	err = binary.Read(file, endianness, &writeTime)
	if err != nil {
		return lnk, err
	}
	lnk.WriteTime = windowsNanoToTime(writeTime)

	err = binary.Read(file, endianness, &lnk.FileSize)
	if err != nil {
		return lnk, err
	}

	err = binary.Read(file, endianness, &lnk.IconIndex)
	if err != nil {
		return lnk, err
	}

	err = binary.Read(file, endianness, &lnk.ShowCommand)
	if err != nil {
		return lnk, err
	}

	err = binary.Read(file, endianness, &lnk.HotKeyLowByte)
	if err != nil {
		return lnk, err
	}

	err = binary.Read(file, endianness, &lnk.HotKeyHighByte)
	if err != nil {
		return lnk, err
	}

	if lnk.HotKeyLowByte < 0x30 || (lnk.HotKeyLowByte > 0x39 && lnk.HotKeyLowByte < 0x41) || (lnk.HotKeyLowByte > 0x5a && lnk.HotKeyLowByte < 0x70) || (lnk.HotKeyLowByte > 0x87 && lnk.HotKeyLowByte < 0x90) || lnk.HotKeyLowByte > 0x91 {
		return lnk, ErrInvalidHotKey
	}
	if lnk.HotKeyLowByte >= 0x70 && lnk.HotKeyLowByte <= 0x87 {
		lnk.HotKey.Key = "F" + strconv.Itoa(int(lnk.HotKeyLowByte-0x6f))
	} else if lnk.HotKeyLowByte == 0x90 {
		lnk.HotKey.Key = "NumLk"
	} else if lnk.HotKeyLowByte == 0x91 {
		lnk.HotKey.Key = "ScrLK"
	} else {
		lnk.HotKey.Key = string(lnk.HotKeyLowByte)
	}
	lnk.HotKey.Shift = lnk.HotKeyHighByte&1 != 0
	lnk.HotKey.Ctrl = lnk.HotKeyHighByte&2 != 0
	lnk.HotKey.Alt = lnk.HotKeyHighByte&4 != 0

	var reserved1 uint16
	err = binary.Read(file, endianness, &reserved1)
	if err != nil {
		return lnk, err
	}

	var reserved2 uint32
	err = binary.Read(file, endianness, &reserved2)
	if err != nil {
		return lnk, err
	}

	var reserved3 uint32
	err = binary.Read(file, endianness, &reserved3)
	if err != nil {
		return lnk, err
	}

	if reserved1 != 0 || reserved2 != 0 || reserved3 != 0 {
		return lnk, ErrReservedBitSet
	}

	if lnk.HasTargetIDList {
		err = binary.Read(file, endianness, &lnk.IDListSize)
		if err != nil {
			return lnk, err
		}
		lnk.IDListBytes = make([]byte, lnk.IDListSize)
		_, err = file.Read(lnk.IDListBytes)
		if err != nil {
			return lnk, err
		}
	}

	if lnk.HasLinkInfo {
		err = binary.Read(file, endianness, &lnk.LinkInfoSize)
		if err != nil {
			return lnk, err
		}

		err = binary.Read(file, endianness, &lnk.LinkInfoHeaderSize)
		if err != nil {
			return lnk, err
		}

		err = binary.Read(file, endianness, &lnk.LinkInfoFlags)
		if err != nil {
			return lnk, err
		}
		lnk.VolumeIDAndLocalBasePath = lnk.LinkInfoFlags&1 != 0
		lnk.CommonNetworkRelativeLinkAndPathSuffix = lnk.LinkInfoFlags&2 != 0

		err = binary.Read(file, endianness, &lnk.VolumeIDOffset)
		if err != nil {
			return lnk, err
		}

		err = binary.Read(file, endianness, &lnk.LocalBasePathOffset)
		if err != nil {
			return lnk, err
		}

		err = binary.Read(file, endianness, &lnk.CommonNetworkRelativeLinkOffset)
		if err != nil {
			return lnk, err
		}

		err = binary.Read(file, endianness, &lnk.CommonPathSuffixOffset)
		if err != nil {
			return lnk, err
		}

		if lnk.LinkInfoHeaderSize > 28 {
			err = binary.Read(file, endianness, &lnk.LocalBasePathOffsetUnicode)
			if err != nil {
				return lnk, err
			}
		}

		if lnk.LinkInfoHeaderSize > 32 {
			err = binary.Read(file, endianness, &lnk.CommonPathSuffixOffsetUnicode)
			if err != nil {
				return lnk, err
			}
		}

		if lnk.VolumeIDAndLocalBasePath {
			err = binary.Read(file, endianness, &lnk.VolumeIDSize)
			if err != nil {
				return lnk, err
			}

			err = binary.Read(file, endianness, &lnk.DriveType)
			if err != nil {
				return lnk, err
			}

			err = binary.Read(file, endianness, &lnk.DriveSerialNumber)
			if err != nil {
				return lnk, err
			}

			err = binary.Read(file, endianness, &lnk.VolumeLabelOffset)
			if err != nil {
				return lnk, err
			}

			if lnk.VolumeLabelOffset > 16 {
				err = binary.Read(file, endianness, &lnk.VolumeLabelOffsetUnicode)
				if err != nil {
					return lnk, err
				}
			}

			lnk.VolumeLabel, err = reader.ReadString('\x00')
			if err != nil {
				return lnk, err
			}
			lnk.VolumeLabel = strings.Trim(lnk.VolumeLabel, "\x00")

			lnk.LocalBasePath, err = reader.ReadString('\x00')
			if err != nil {
				return lnk, err
			}
			lnk.LocalBasePath = strings.Trim(lnk.LocalBasePath, "\x00")
		}
	}

	return lnk, nil
}

// The Windows epoch is 1601-01-01, while the Unix epoch is 1970-01-01.
func windowsNanoToTime(windowsNano uint64) time.Time {
	// fmt.Println(time.Unix((windowsNano-116444736000000000)/10000000, 0))
	// fmt.Println(time.Unix(0, 1000000000*((windowsNano-116444736000000000)/10000000)))
	// fmt.Println(time.Unix(0, 100*windowsNano-11644473600000000000))
	// fmt.Println(time.Unix(0, 100*(windowsNano-116444736000000000)))

	// this converts the Windows nanoseconds to Unix nanoseconds
	return time.Unix(0, int64(100*windowsNano-11644473600000000000))
}
