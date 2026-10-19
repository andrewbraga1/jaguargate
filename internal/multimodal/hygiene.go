package multimodal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var (
	ErrDisallowedMimeType = errors.New("disallowed multimodal MIME type")
	ErrInvalidMagicBytes  = errors.New("file magic bytes do not match declared MIME type")
	ErrCorruptedBase64    = errors.New("corrupted base64 media payload")
)

// HygieneResult holds the outcome of inspecting and scrubbing a multimodal Data URI.
type HygieneResult struct {
	CleanedDataURI   string
	MimeType         string
	MetadataStripped bool
	ViolationCode    string // "JG-SEC-403" when suspicious metadata or mismatched magic bytes are found
	Err              error
}

// IsDataURI quickly checks if a string is a Base64 Data URI (e.g., "data:image/jpeg;base64,...").
func IsDataURI(s string) bool {
	return strings.HasPrefix(s, "data:") && strings.Contains(s, ";base64,")
}

// SanitizeDataURI verifies MIME whitelist, checks binary Magic Bytes, and strips hidden EXIF/XMP/Comment segments.
func SanitizeDataURI(dataURI string, cfg config.MultimodalConfig) HygieneResult {
	commaIdx := strings.IndexByte(dataURI, ',')
	if commaIdx == -1 || !strings.HasPrefix(dataURI, "data:") {
		return HygieneResult{CleanedDataURI: dataURI}
	}

	header := dataURI[:commaIdx] // e.g., "data:image/jpeg;base64"
	b64Payload := dataURI[commaIdx+1:]

	mimeType := strings.TrimPrefix(header, "data:")
	mimeType = strings.TrimSuffix(mimeType, ";base64")
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))

	// 1. Check MIME type whitelist
	if len(cfg.AllowedMimeTypes) > 0 {
		allowed := false
		for _, m := range cfg.AllowedMimeTypes {
			if strings.EqualFold(m, mimeType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return HygieneResult{
				CleanedDataURI: "[JG-MEDIA-REMOVED]",
				MimeType:       mimeType,
				ViolationCode:  "JG-SEC-403",
				Err:            ErrDisallowedMimeType,
			}
		}
	}

	rawBytes, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return HygieneResult{
			CleanedDataURI: "[JG-MEDIA-REMOVED]",
			MimeType:       mimeType,
			ViolationCode:  "JG-SEC-403",
			Err:            ErrCorruptedBase64,
		}
	}

	// 2. Verify binary Magic Bytes against declared MIME type
	if cfg.VerifyMagicBytes {
		if !verifyMagicBytes(mimeType, rawBytes) {
			return HygieneResult{
				CleanedDataURI: "[JG-MEDIA-REMOVED]",
				MimeType:       mimeType,
				ViolationCode:  "JG-SEC-403",
				Err:            ErrInvalidMagicBytes,
			}
		}
	}

	// 3. Strip hidden EXIF / XMP / Comment metadata segments where prompt injections hide
	if cfg.StripEXIFXMPMetadata {
		switch mimeType {
		case "image/jpeg":
			cleaned, stripped := StripJPEGMetadata(rawBytes)
			if stripped {
				reEncoded := base64.StdEncoding.EncodeToString(cleaned)
				return HygieneResult{
					CleanedDataURI:   header + "," + reEncoded,
					MimeType:         mimeType,
					MetadataStripped: true,
					ViolationCode:    "JG-SEC-403",
				}
			}
		case "image/png":
			cleaned, stripped := StripPNGMetadata(rawBytes)
			if stripped {
				reEncoded := base64.StdEncoding.EncodeToString(cleaned)
				return HygieneResult{
					CleanedDataURI:   header + "," + reEncoded,
					MimeType:         mimeType,
					MetadataStripped: true,
					ViolationCode:    "JG-SEC-403",
				}
			}
		}
	}

	return HygieneResult{
		CleanedDataURI: dataURI,
		MimeType:       mimeType,
	}
}

func verifyMagicBytes(mimeType string, data []byte) bool {
	switch mimeType {
	case "image/jpeg":
		return len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF
	case "image/png":
		return len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'})
	case "image/webp":
		return len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP"))
	case "application/pdf":
		return len(data) >= 5 && bytes.Equal(data[:5], []byte("%PDF-"))
	default:
		return false
	}
}

// StripJPEGMetadata removes APP1..APP15 (0xFFE1..0xFFEF, including EXIF & XMP) and COM (0xFFFE) segments
// without decoding or degrading image pixels.
func StripJPEGMetadata(data []byte) ([]byte, bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return data, false
	}

	out := make([]byte, 0, len(data))
	out = append(out, 0xFF, 0xD8) // SOI (Start of Image)
	stripped := false
	i := 2

	for i < len(data) {
		if data[i] != 0xFF {
			// Reached compressed image scan data or malformed stream; copy remainder intact
			out = append(out, data[i:]...)
			break
		}

		// Skip padding 0xFF bytes
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			break
		}

		marker := data[i]
		i++

		// Standalone markers without length fields (SOI, EOI, RST0..RST7)
		if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) {
			out = append(out, 0xFF, marker)
			if marker == 0xD9 {
				break
			}
			continue
		}

		// Ensure at least 2 bytes exist for segment length
		if i+2 > len(data) {
			out = append(out, 0xFF, marker)
			out = append(out, data[i:]...)
			break
		}

		segLen := int(data[i])<<8 | int(data[i+1])
		if segLen < 2 || i+segLen > len(data) {
			// Malformed segment length; preserve remaining bytes safely
			out = append(out, 0xFF, marker)
			out = append(out, data[i:]...)
			break
		}

		// APP1..APP15 (0xE1..0xEF: EXIF, XMP, ICC, Adobe) or COM (0xFE: Comment)
		if (marker >= 0xE1 && marker <= 0xEF) || marker == 0xFE {
			stripped = true
			i += segLen
			continue
		}

		// Keep legitimate structural segment (e.g., APP0 JFIF 0xE0, DQT, DHT, SOF0)
		out = append(out, 0xFF, marker)
		out = append(out, data[i:i+segLen]...)
		i += segLen

		// SOS (Start of Scan 0xDA): raw entropy-coded pixel data follows until EOI
		if marker == 0xDA {
			out = append(out, data[i:]...)
			break
		}
	}

	return out, stripped
}

// StripPNGMetadata removes textual ancillary chunks (tEXt, zTXt, iTXt, eXIf) from PNG binaries.
func StripPNGMetadata(data []byte) ([]byte, bool) {
	pngSig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}
	if len(data) < 8 || !bytes.Equal(data[:8], pngSig) {
		return data, false
	}

	out := make([]byte, 0, len(data))
	out = append(out, pngSig...)
	stripped := false
	i := 8

	for i+8 <= len(data) {
		chunkLen := int(uint32(data[i])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3]))
		chunkType := string(data[i+4 : i+8])
		totalChunkBytes := 4 + 4 + chunkLen + 4 // Length + Type + Data + CRC32

		if chunkLen < 0 || i+totalChunkBytes > len(data) {
			out = append(out, data[i:]...)
			break
		}

		switch chunkType {
		case "tEXt", "zTXt", "iTXt", "eXIf":
			stripped = true
			i += totalChunkBytes
			continue
		default:
			out = append(out, data[i:i+totalChunkBytes]...)
			i += totalChunkBytes
		}

		if chunkType == "IEND" {
			break
		}
	}

	return out, stripped
}
