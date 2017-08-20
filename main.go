package lnk

import (
	"encoding/binary"
	"strconv"
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
// Conforms to protocol revision 3.0, published on 2017-06-01.
//
// https://msdn.microsoft.com/library/dd871305.aspx
type LNK struct {
	// ShellLinkHeader (https://msdn.microsoft.com/library/dd891343.aspx)
	// LinkFlags (https://msdn.microsoft.com/library/dd891314.aspx)
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
	// FileAttributes (https://msdn.microsoft.com/library/dd871338.aspx)
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
	// ShellLinkHeader (https://msdn.microsoft.com/library/dd891343.aspx)
	CreationTime time.Time
	AccessTime   time.Time
	WriteTime    time.Time
	FileSize     uint32
	IconIndex    int32
	ShowCommand  uint32
	HotKey       HotKey

	// LinkTargetIDList (https://msdn.microsoft.com/library/dd891268.aspx)
	// IDList (https://msdn.microsoft.com/library/dd871365.aspx)
	IDListBytes []byte

	// LinkInfo (https://msdn.microsoft.com/library/dd871404.aspx)
	LinkInfoHeaderSize                     uint32
	VolumeIDAndLocalBasePath               bool
	CommonNetworkRelativeLinkAndPathSuffix bool
	VolumeIDOffset                         uint32
	LocalBasePathOffset                    uint32
	CommonNetworkRelativeLinkOffset        uint32
	CommonPathSuffixOffset                 uint32
	LocalBasePathOffsetUnicode             uint32
	CommonPathSuffixOffsetUnicode          uint32
	// VolumeID (https://msdn.microsoft.com/library/dd891327.aspx)
	VolumeIDSize             uint32
	DriveType                uint32
	DriveSerialNumber        uint32
	VolumeLabelOffset        uint32
	VolumeLabelOffsetUnicode uint32
	VolumeLabel              string
	// LinkInfo (https://msdn.microsoft.com/library/dd871404.aspx)
	LocalBasePath string
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

var endianness = binary.LittleEndian

// 00021401-0000-0000-C000-000000000046
var validCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0xc0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
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
