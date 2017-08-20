package lnk

import (
	"bufio"
	"encoding/binary"
	"errors"
	"strings"
)

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

// Open parses an io.Reader into a LNK.
func Open(file *bufio.Reader) (*LNK, error) {
	lnk := new(LNK)

	// ShellLinkHeader
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
	hasTargetIDList := linkFlags&(1<<0) != 0
	lnk.HasLinkInfo = linkFlags&(1<<1) != 0
	lnk.HasName = linkFlags&(1<<2) != 0
	lnk.HasRelativePath = linkFlags&(1<<3) != 0
	lnk.HasWorkingDir = linkFlags&(1<<4) != 0
	lnk.HasArguments = linkFlags&(1<<5) != 0
	lnk.HasIconLocation = linkFlags&(1<<6) != 0
	lnk.IsUnicode = linkFlags&(1<<7) != 0
	lnk.ForceNoLinkInfo = linkFlags&(1<<8) != 0
	lnk.HasExpString = linkFlags&(1<<9) != 0
	lnk.RunInSeperateProcess = linkFlags&(1<<10) != 0
	// Unused1
	lnk.HasDarwinID = linkFlags&(1<<12) != 0
	lnk.RunAsUser = linkFlags&(1<<13) != 0
	lnk.HasExpIcon = linkFlags&(1<<14) != 0
	lnk.NoPidlAlias = linkFlags&(1<<15) != 0
	// Unused2
	lnk.RunWithShimLayer = linkFlags&(1<<17) != 0
	lnk.ForceNoLinkTrack = linkFlags&(1<<18) != 0
	lnk.EnableTargetMetadata = linkFlags&(1<<19) != 0
	lnk.DisableLinkPathTracking = linkFlags&(1<<20) != 0
	lnk.DisableKnownFolderTracking = linkFlags&(1<<21) != 0
	lnk.DisableKnownFolderAlias = linkFlags&(1<<22) != 0
	lnk.AllowLinkToLink = linkFlags&(1<<23) != 0
	lnk.UnaliasOnSave = linkFlags&(1<<24) != 0
	lnk.PreferEnvironmentPath = linkFlags&(1<<25) != 0
	lnk.KeepLocalIDListForUNCTarget = linkFlags&(1<<26) != 0

	var fileAttributes uint32
	err = binary.Read(file, endianness, &fileAttributes)
	if err != nil {
		return lnk, err
	}
	lnk.ReadOnly = fileAttributes&(1<<0) != 0
	lnk.Hidden = fileAttributes&(1<<1) != 0
	lnk.System = fileAttributes&(1<<2) != 0
	// Reserved1
	lnk.Directory = fileAttributes&(1<<4) != 0
	lnk.Archive = fileAttributes&(1<<5) != 0
	// Reserved2
	lnk.Normal = fileAttributes&(1<<7) != 0
	lnk.Temporary = fileAttributes&(1<<8) != 0
	lnk.SparseFile = fileAttributes&(1<<9) != 0
	lnk.ReparsePoint = fileAttributes&(1<<10) != 0
	lnk.Compressed = fileAttributes&(1<<11) != 0
	lnk.Offline = fileAttributes&(1<<12) != 0
	lnk.NotContentIndexed = fileAttributes&(1<<13) != 0
	lnk.Encrypted = fileAttributes&(1<<14) != 0
	if fileAttributes&(1<<3) != 0 || fileAttributes&(1<<6) != 0 {
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
	lnk.HotKey.Shift = highByte&(1<<0) != 0
	lnk.HotKey.Ctrl = highByte&(1<<1) != 0
	lnk.HotKey.Alt = highByte&(1<<2) != 0

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

	// LinkTargetIDList
	if hasTargetIDList {
		var idListSize uint16
		err = binary.Read(file, endianness, &idListSize)
		if err != nil {
			return lnk, err
		}
		lnk.IDListBytes = make([]byte, idListSize)
		_, err = file.Read(lnk.IDListBytes)
		if err != nil {
			return lnk, err
		}
	}

	// LinkInfo
	if lnk.HasLinkInfo {
		// LinkInfoSize
		_, err = file.Discard(4)
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
		lnk.VolumeIDAndLocalBasePath = linkInfoFlags&(1<<0) != 0
		lnk.CommonNetworkRelativeLinkAndPathSuffix = linkInfoFlags&(1<<1) != 0

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

			lnk.VolumeLabel, err = file.ReadString('\x00')
			if err != nil {
				return lnk, err
			}
			lnk.VolumeLabel = strings.Trim(lnk.VolumeLabel, "\x00")

			lnk.LocalBasePath, err = file.ReadString('\x00')
			if err != nil {
				return lnk, err
			}
			lnk.LocalBasePath = strings.Trim(lnk.LocalBasePath, "\x00")
		}
	}

	return lnk, nil
}
