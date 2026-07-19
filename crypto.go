package clicore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

const (
	EncryptionAlgoAES256GCM = "aes256gcm"
	chunkSize               = 64 * 1024
	headerSize              = 18
	// maxChunkCiphertext caps a single framed chunk so a hostile stream cannot
	// force a huge allocation. A chunk is at most chunkSize of plaintext plus the
	// GCM tag; the slack absorbs the tag and any future framing bytes.
	maxChunkCiphertext = chunkSize + 64
)

const (
	encVersionMajor = 1
	// encVersionLegacy (1,1) terminated the stream with an UNAUTHENTICATED
	// zero-length marker, so a tail-truncated ciphertext decrypted as a clean
	// EOF. Still read for backward compatibility; never written.
	encVersionLegacy = 1
	// encVersionAEAD (1,2) authenticates end-of-stream: every chunk carries a
	// final flag bound into the AEAD additional data, so truncation (or any
	// header/format tampering) fails the tag instead of passing silently.
	encVersionAEAD = 2
)

var (
	encryptionMagic = [4]byte{'S', '2', 'E', '1'}
	ErrInvalidKey   = errors.New("invalid encryption key")
)

type DeviceKeyPair struct {
	PublicKey  string
	PrivateKey string
}

func NewDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func NewDeviceKeyPair() (DeviceKeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceKeyPair{}, err
	}
	return DeviceKeyPair{
		PublicKey:  encodeDeviceKey(publicKey[:]),
		PrivateKey: encodeDeviceKey(privateKey[:]),
	}, nil
}

func SealContentKeyForDevice(contentKey []byte, targetPublicKey string) (string, error) {
	if len(contentKey) != 32 {
		return "", ErrInvalidKey
	}
	publicKey, err := decodeDeviceKey(targetPublicKey)
	if err != nil {
		return "", err
	}
	var public [32]byte
	copy(public[:], publicKey)
	sealed, err := box.SealAnonymous(nil, contentKey, &public, rand.Reader)
	if err != nil {
		return "", err
	}
	return encodeDeviceKey(sealed), nil
}

func OpenSealedContentKey(sealedKey, publicKey, privateKey string) ([]byte, error) {
	sealed, err := decodeDeviceEnvelope(sealedKey)
	if err != nil {
		return nil, err
	}
	publicRaw, err := decodeDeviceKey(publicKey)
	if err != nil {
		return nil, err
	}
	privateRaw, err := decodeDeviceKey(privateKey)
	if err != nil {
		return nil, err
	}
	var public [32]byte
	var private [32]byte
	copy(public[:], publicRaw)
	copy(private[:], privateRaw)
	opened, ok := box.OpenAnonymous(nil, sealed, &public, &private)
	if !ok {
		return nil, errors.New("open sealed content key: authentication failed")
	}
	if len(opened) != 32 {
		return nil, ErrInvalidKey
	}
	return opened, nil
}

func encodeDeviceKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func decodeDeviceKey(encoded string) ([]byte, error) {
	raw, err := decodeFlexibleBase64(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, ErrInvalidKey
	}
	return raw, nil
}

func decodeDeviceEnvelope(encoded string) ([]byte, error) {
	raw, err := decodeFlexibleBase64(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != 80 {
		return nil, errors.New("invalid sealed content key")
	}
	return raw, nil
}

func decodeFlexibleBase64(encoded string) ([]byte, error) {
	value := strings.TrimSpace(encoded)
	decoders := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	var last error
	for _, decoder := range decoders {
		raw, err := decoder.DecodeString(value)
		if err == nil {
			return raw, nil
		}
		last = err
	}
	return nil, last
}

func EncryptStream(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	nonceBase := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonceBase); err != nil {
		return err
	}
	header := make([]byte, 0, headerSize)
	header = append(header, encryptionMagic[:]...)
	header = append(header, encVersionMajor, encVersionAEAD)
	header = append(header, nonceBase...)
	if _, err := dst.Write(header); err != nil {
		return err
	}
	// One-chunk lookahead so the last chunk can be flagged final before it is
	// sealed. The final flag is authenticated (folded into the AAD), which is
	// what makes a truncated tail detectable on decrypt.
	bufs := [2][]byte{make([]byte, chunkSize), make([]byte, chunkSize)}
	cur := 0
	n, eof, err := readChunk(src, bufs[cur])
	if err != nil {
		return err
	}
	for counter := uint64(0); ; counter++ {
		if eof {
			// The current chunk is the last one (empty on an empty input).
			return writeSealedChunk(dst, aead, header, nonceBase, counter, bufs[cur][:n], true)
		}
		nxt := 1 - cur
		n2, eof2, rerr := readChunk(src, bufs[nxt])
		if rerr != nil {
			return rerr
		}
		if eof2 && n2 == 0 {
			// Nothing follows the current chunk, so it is the final one.
			return writeSealedChunk(dst, aead, header, nonceBase, counter, bufs[cur][:n], true)
		}
		if err := writeSealedChunk(dst, aead, header, nonceBase, counter, bufs[cur][:n], false); err != nil {
			return err
		}
		cur, n, eof = nxt, n2, eof2
	}
}

// readChunk fills buf with up to len(buf) bytes. eof reports that the stream is
// exhausted; n may still be > 0 when the final chunk is short.
func readChunk(src io.Reader, buf []byte) (n int, eof bool, err error) {
	n, err = io.ReadFull(src, buf)
	switch err {
	case nil:
		return n, false, nil
	case io.EOF:
		return 0, true, nil
	case io.ErrUnexpectedEOF:
		return n, true, nil
	default:
		return 0, false, err
	}
}

func DecryptStream(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("read encrypted header: %w", err)
	}
	if string(header[:4]) != string(encryptionMagic[:]) || header[4] != encVersionMajor {
		return errors.New("unsupported encrypted share format")
	}
	nonceBase := header[6:]
	switch header[5] {
	case encVersionAEAD:
		return decryptStreamAEAD(dst, src, aead, header, nonceBase)
	case encVersionLegacy:
		return decryptStreamLegacy(dst, src, aead, nonceBase)
	default:
		return errors.New("unsupported encrypted share format")
	}
}

// decryptStreamAEAD reads the authenticated (1,2) framing. Each chunk is
// [uint32 len][finalByte][ciphertext]; the finalByte is bound into the AAD, so
// only the encryptor can produce the end-of-stream chunk. A stream that ends
// without a final chunk (a truncated tail) surfaces as an error rather than a
// silent short read.
func decryptStreamAEAD(dst io.Writer, src io.Reader, aead cipher.AEAD, header, nonceBase []byte) error {
	for counter := uint64(0); ; counter++ {
		var length uint32
		if err := binary.Read(src, binary.BigEndian, &length); err != nil {
			return fmt.Errorf("encrypted stream ended before the final chunk (truncated?): %w", err)
		}
		if length == 0 || length > maxChunkCiphertext {
			return errors.New("invalid encrypted chunk length")
		}
		var finalByte [1]byte
		if _, err := io.ReadFull(src, finalByte[:]); err != nil {
			return fmt.Errorf("read encrypted chunk flag: %w", err)
		}
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return fmt.Errorf("read encrypted chunk: %w", err)
		}
		plaintext, err := aead.Open(nil, nonceFor(nonceBase, counter), ciphertext, chunkAAD(header, finalByte[0]))
		if err != nil {
			return fmt.Errorf("decrypt encrypted share: %w", err)
		}
		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
		if finalByte[0] == 1 {
			return nil
		}
	}
}

// decryptStreamLegacy reads the pre-1.2 (1,1) framing for shares encrypted
// before the authenticated terminator existed. It is truncation-vulnerable by
// construction (the zero-length terminator is unauthenticated); kept only so old
// ciphertexts remain readable. New shares are always written as 1.2.
func decryptStreamLegacy(dst io.Writer, src io.Reader, aead cipher.AEAD, nonceBase []byte) error {
	for counter := uint64(0); ; counter++ {
		var length uint32
		if err := binary.Read(src, binary.BigEndian, &length); err != nil {
			return fmt.Errorf("read encrypted chunk length: %w", err)
		}
		if length == 0 {
			return nil
		}
		if length > maxChunkCiphertext {
			return errors.New("invalid encrypted chunk length")
		}
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return fmt.Errorf("read encrypted chunk: %w", err)
		}
		plaintext, err := aead.Open(nil, nonceFor(nonceBase, counter), ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decrypt encrypted share: %w", err)
		}
		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
	}
}

func ShareURLWithKey(base, publicID string, key []byte) string {
	base = strings.TrimRight(base, "/")
	return base + "/" + publicID + "#k=" + EncodeKey(key)
}

func KeyFromShareURL(raw string) ([]byte, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		return nil, err
	}
	return DecodeKey(values.Get("k"))
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// writeSealedChunk emits one authenticated chunk: [uint32 len][finalByte][ct].
// The final flag is carried in the AAD (see chunkAAD), so the end-of-stream
// signal cannot be forged or moved by anyone without the key.
func writeSealedChunk(dst io.Writer, aead cipher.AEAD, header, nonceBase []byte, counter uint64, plaintext []byte, final bool) error {
	finalByte := byte(0)
	if final {
		finalByte = 1
	}
	ciphertext := aead.Seal(nil, nonceFor(nonceBase, counter), plaintext, chunkAAD(header, finalByte))
	if len(ciphertext) > int(^uint32(0)) {
		return errors.New("encrypted chunk too large")
	}
	if err := binary.Write(dst, binary.BigEndian, uint32(len(ciphertext))); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{finalByte}); err != nil {
		return err
	}
	_, err := dst.Write(ciphertext)
	return err
}

// chunkAAD binds the header (magic, version, nonce base) and the end-of-stream
// flag into a chunk's additional authenticated data. Tampering with the format
// version, the nonce base, or the final flag then fails the GCM tag.
func chunkAAD(header []byte, finalByte byte) []byte {
	aad := make([]byte, 0, len(header)+1)
	aad = append(aad, header...)
	aad = append(aad, finalByte)
	return aad
}

func nonceFor(base []byte, counter uint64) []byte {
	nonce := append([]byte(nil), base...)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], counter)
	return nonce
}
