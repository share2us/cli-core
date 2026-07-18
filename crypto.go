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
	header = append(header, 1, 1)
	header = append(header, nonceBase...)
	if _, err := dst.Write(header); err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	for counter := uint64(0); ; counter++ {
		n, readErr := io.ReadFull(src, buf)
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			if n > 0 {
				if err := writeEncryptedChunk(dst, aead, nonceBase, counter, buf[:n]); err != nil {
					return err
				}
			}
			return binary.Write(dst, binary.BigEndian, uint32(0))
		}
		if readErr != nil {
			return readErr
		}
		if err := writeEncryptedChunk(dst, aead, nonceBase, counter, buf); err != nil {
			return err
		}
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
	if string(header[:4]) != string(encryptionMagic[:]) || header[4] != 1 || header[5] != 1 {
		return errors.New("unsupported encrypted share format")
	}
	nonceBase := header[6:]
	for counter := uint64(0); ; counter++ {
		var length uint32
		if err := binary.Read(src, binary.BigEndian, &length); err != nil {
			return fmt.Errorf("read encrypted chunk length: %w", err)
		}
		if length == 0 {
			return nil
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

func writeEncryptedChunk(dst io.Writer, aead cipher.AEAD, nonceBase []byte, counter uint64, plaintext []byte) error {
	ciphertext := aead.Seal(nil, nonceFor(nonceBase, counter), plaintext, nil)
	if len(ciphertext) > int(^uint32(0)) {
		return errors.New("encrypted chunk too large")
	}
	if err := binary.Write(dst, binary.BigEndian, uint32(len(ciphertext))); err != nil {
		return err
	}
	_, err := dst.Write(ciphertext)
	return err
}

func nonceFor(base []byte, counter uint64) []byte {
	nonce := append([]byte(nil), base...)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], counter)
	return nonce
}
