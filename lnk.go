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
// https://msdn.microsoft.com/en-us/library/dd891253.aspx
// https://github.com/libyal/liblnk/blob/15ec0a6ea940e79048ceee71861546485c4ab6d8/documentation/Windows%20Shortcut%20File%20%28LNK%29%20format.asciidoc
type LNK struct {
	// ShellLinkHeader
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
	ReadOnly                    bool
	Hidden                      bool
	System                      bool
	Directory                   bool
	Archive                     bool
	Normal                      bool
	Temporary                   bool
	SparseFile                  bool
	ReparsePoint                bool
	Compressed                  bool
	Offline                     bool
	NotContentIndexed           bool
	Encrypted                   bool
	CreationTime                time.Time
	AccessTime                  time.Time
	WriteTime                   time.Time
	FileSize                    uint32
	IconIndex                   int32
	// If ShowCommand does not equal ShowNormal, ShowMaximized, or
	// ShowMinNoActive, ShowCommand must be treated as ShowNormal.
	ShowCommand uint32
	HotKey      HotKey
	// LinkTargetIDList
	IDListSize  uint16
	IDListBytes []byte
	// LinkInfo
	LinkInfoSize                           uint32
	LinkInfoHeaderSize                     uint32
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

type HotKey struct {
	// LowByte
	Key byte

	Shift bool
	Ctrl  bool
	Alt   bool
}

func (hotKey HotKey) String() string {
	var str string

	if hotKey.Shift {
		str += "Shift+"
	}

	if hotKey.Ctrl {
		str += "Ctrl+"
	}

	if hotKey.Alt {
		str += "Alt+"
	}

	if hotKey.Key >= 0x70 && hotKey.Key <= 0x87 {
		str += "F" + strconv.Itoa(int(hotKey.Key-0x6f))
	} else if hotKey.Key == 0x90 {
		str += "NumLk"
	} else if hotKey.Key == 0x91 {
		str += "ScrLK"
	} else {
		str += string(hotKey.Key)
	}

	return str
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

// Open parses an io.Reader into a LNK.
func Open(file io.Reader) (*LNK, error) {
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

	var linkFlags uint32
	err = binary.Read(file, endianness, &linkFlags)
	if err != nil {
		return lnk, err
	}
	lnk.HasTargetIDList = linkFlags&0x00000001 != 0
	lnk.HasLinkInfo = linkFlags&0x00000002 != 0
	lnk.HasName = linkFlags&0x00000004 != 0
	lnk.HasRelativePath = linkFlags&0x00000008 != 0
	lnk.HasWorkingDir = linkFlags&0x00000010 != 0
	lnk.HasArguments = linkFlags&0x00000020 != 0
	lnk.HasIconLocation = linkFlags&0x00000040 != 0
	lnk.IsUnicode = linkFlags&0x00000080 != 0
	lnk.ForceNoLinkInfo = linkFlags&0x00000100 != 0
	lnk.HasExpString = linkFlags&0x00000200 != 0
	lnk.RunInSeperateProcess = linkFlags&0x00000400 != 0
	// Unused1
	lnk.HasDarwinID = linkFlags&0x00001000 != 0
	lnk.RunAsUser = linkFlags&0x00002000 != 0
	lnk.HasExpIcon = linkFlags&0x00004000 != 0
	lnk.NoPidlAlias = linkFlags&0x00008000 != 0
	// Unused2
	lnk.RunWithShimLayer = linkFlags&0x00020000 != 0
	lnk.ForceNoLinkTrack = linkFlags&0x00040000 != 0
	lnk.EnableTargetMetadata = linkFlags&0x00080000 != 0
	lnk.DisableLinkPathTracking = linkFlags&0x00100000 != 0
	lnk.DisableKnownFolderTracking = linkFlags&0x00200000 != 0
	lnk.DisableKnownFolderAlias = linkFlags&0x00400000 != 0
	lnk.AllowLinkToLink = linkFlags&0x00800000 != 0
	lnk.UnaliasOnSave = linkFlags&0x01000000 != 0
	lnk.PreferEnvironmentPath = linkFlags&0x02000000 != 0
	lnk.KeepLocalIDListForUNCTarget = linkFlags&0x04000000 != 0

	var fileAttributes uint32
	err = binary.Read(file, endianness, &fileAttributes)
	if err != nil {
		return lnk, err
	}
	lnk.ReadOnly = fileAttributes&0x00000001 != 0
	lnk.Hidden = fileAttributes&0x00000002 != 0
	lnk.System = fileAttributes&0x00000004 != 0
	// Reserved1
	lnk.Directory = fileAttributes&0x00000010 != 0
	lnk.Archive = fileAttributes&0x00000020 != 0
	// Reserved2
	lnk.Normal = fileAttributes&0x00000080 != 0
	lnk.Temporary = fileAttributes&0x00000100 != 0
	lnk.SparseFile = fileAttributes&0x00000200 != 0
	lnk.ReparsePoint = fileAttributes&0x00000400 != 0
	lnk.Compressed = fileAttributes&0x00000800 != 0
	lnk.Offline = fileAttributes&0x00001000 != 0
	lnk.NotContentIndexed = fileAttributes&0x00002000 != 0
	lnk.Encrypted = fileAttributes&0x00004000 != 0
	if fileAttributes&0x00000008 != 0 || fileAttributes&0x00000040 != 0 {
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

	err = binary.Read(file, endianness, &lnk.HotKey.Key)
	if err != nil {
		return lnk, err
	}
	if lnk.HotKey.Key < 0x30 || (lnk.HotKey.Key > 0x39 && lnk.HotKey.Key < 0x41) || (lnk.HotKey.Key > 0x5a && lnk.HotKey.Key < 0x70) || (lnk.HotKey.Key > 0x87 && lnk.HotKey.Key < 0x90) || lnk.HotKey.Key > 0x91 {
		return lnk, ErrInvalidHotKey
	}

	var highByte byte
	err = binary.Read(file, endianness, &highByte)
	if err != nil {
		return lnk, err
	}
	lnk.HotKey.Shift = highByte&0x01 != 0
	lnk.HotKey.Ctrl = highByte&0x02 != 0
	lnk.HotKey.Alt = highByte&0x04 != 0

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

		var linkInfoFlags uint32
		err = binary.Read(file, endianness, &linkInfoFlags)
		if err != nil {
			return lnk, err
		}
		lnk.VolumeIDAndLocalBasePath = linkInfoFlags&1 != 0
		lnk.CommonNetworkRelativeLinkAndPathSuffix = linkInfoFlags&2 != 0

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
