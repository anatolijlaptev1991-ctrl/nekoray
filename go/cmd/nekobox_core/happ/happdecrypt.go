// Package happdecrypt implements decryption of encrypted Happ subscription
// links (happ://crypt .. happ://crypt5) used by proxy providers.
//
// The algorithm and the RSA key material mirror the reference implementation
// github.com/amurcanov/happ-decrypt-universal (Apache-2.0); the keys are the
// ones published in github.com/XuliGan4eg2006/Happ-converter. Both references
// were cross-validated against each other before porting.
package happdecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed assets/native_keys.json
var nativeKeysJSON []byte

//go:embed assets/crypt5_final_keys.json
var crypt5KeysJSON []byte

type (
	nativeKeyList struct {
		Keys []string `json:"keys"`
	}
	crypt5KeyMap struct {
		Keys map[string]string `json:"keys"`
	}
)

var (
	keysOnce   sync.Once
	nativeKeys []*rsa.PrivateKey
	crypt5Keys map[string]string
	keysErr    error
)

var prefixes = []struct {
	prefix string
	mode   int
}{
	{"happ://crypt5/", 4},
	{"happ://crypt4/", 3},
	{"happ://crypt3/", 2},
	{"happ://crypt2/", 1},
	{"happ://crypt/", 0},
}

// IsHappLink reports whether the string looks like an encrypted Happ link.
func IsHappLink(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "happ://crypt")
}

func loadKeys() error {
	keysOnce.Do(func() {
		var nk nativeKeyList
		if err := json.Unmarshal(nativeKeysJSON, &nk); err != nil {
			keysErr = fmt.Errorf("invalid native keys: %w", err)
			return
		}
		for _, encoded := range nk.Keys {
			key, err := loadPrivateKey(encoded)
			if err != nil {
				keysErr = err
				return
			}
			nativeKeys = append(nativeKeys, key)
		}
		var ck crypt5KeyMap
		if err := json.Unmarshal(crypt5KeysJSON, &ck); err != nil {
			keysErr = fmt.Errorf("invalid crypt5 keys: %w", err)
			return
		}
		crypt5Keys = ck.Keys
	})
	return keysErr
}

func loadPrivateKey(encodedPrivateKey string) (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key: not RSA")
	}
	return key, nil
}

func b64Decode(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	candidates := []string{text, strings.TrimRight(text, "=")}
	for _, candidate := range candidates {
		padded := candidate + strings.Repeat("=", (4-len(candidate)%4)%4)
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if decoded, err := encoding.DecodeString(padded); err == nil {
				return decoded, nil
			}
		}
	}
	return nil, errors.New("invalid base64")
}

func shuffleBlocks(text string, blockSize int, order []int) string {
	data := []byte(text)
	full := len(data) / blockSize * blockSize
	out := make([]byte, 0, len(data))
	for i := 0; i < full; i += blockSize {
		block := data[i : i+blockSize]
		for _, index := range order {
			out = append(out, block[index])
		}
	}
	return string(append(out, data[full:]...))
}

func m4831f(text string) string {
	return shuffleBlocks(text, 6, []int{1, 3, 5, 0, 2, 4})
}

func inverseM4831f(text string) string {
	return shuffleBlocks(text, 6, []int{3, 0, 4, 1, 5, 2})
}

func m4842j(text string) string {
	return shuffleBlocks(text, 2, []int{1, 0})
}

func permute4(text string) string {
	return shuffleBlocks(text, 4, []int{2, 3, 0, 1})
}

func decryptRSA(ciphertext string, key *rsa.PrivateKey) (string, error) {
	encrypted, err := b64Decode(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, key, encrypted)
	if err != nil {
		return "", fmt.Errorf("rsa decrypt failed: %w", err)
	}
	return string(plaintext), nil
}

func decryptBody(body string, key *rsa.PrivateKey, salt []byte) (string, error) {
	if len(body) < 13 {
		return "", errors.New("crypt5 body is too short")
	}

	nonce := []byte(body[:12])
	lengthStart := 12
	if salt != nil {
		if len(body) < 22 {
			return "", errors.New("crypt5 salted header is too short")
		}
		lengthStart = 22
	}

	lengthEnd := lengthStart
	for lengthEnd < len(body) && body[lengthEnd] >= '0' && body[lengthEnd] <= '9' {
		lengthEnd++
	}
	if lengthEnd == lengthStart {
		return "", errors.New("crypt5 segment length is missing")
	}
	segmentLen, err := strconv.Atoi(body[lengthStart:lengthEnd])
	if err != nil {
		return "", errors.New("crypt5 segment length is missing")
	}
	packed := body[lengthEnd:]
	if len(packed) == 0 || segmentLen > len(packed)-1 {
		return "", errors.New("crypt5 encrypted segment is truncated")
	}
	encryptedSegment := packed[1 : 1+segmentLen]
	rsaCiphertext := packed[1+segmentLen:]

	rsaPlain, err := decryptRSA(rsaCiphertext, key)
	if err != nil {
		return "", err
	}
	chachaKey, err := b64Decode(m4842j(rsaPlain))
	if err != nil {
		return "", err
	}
	if len(chachaKey) != 32 {
		return "", fmt.Errorf("crypt5 ChaCha20 key has invalid length: %d", len(chachaKey))
	}
	if salt != nil {
		// salted layout: the effective key is XORed with an 8-byte salt from
		// the header (newer Happ releases)
		for i := range chachaKey {
			chachaKey[i] ^= salt[i%len(salt)]
		}
	}

	encrypted, err := b64Decode(encryptedSegment)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return "", fmt.Errorf("crypt5 ChaCha20 key has invalid length: %d", len(chachaKey))
	}
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", errors.New("crypt5 ChaCha20-Poly1305 decrypt failed")
	}
	return string(plaintext), nil
}

func decryptCrypt5Middle(ciphertext string) (string, error) {
	shuffled := permute4(inverseM4831f(ciphertext))
	if len(shuffled) < 8 {
		return "", errors.New("crypt5 payload is too short")
	}

	marker := shuffled[:4] + shuffled[len(shuffled)-4:]
	body := shuffled[4 : len(shuffled)-4]
	if len(body) < 13 {
		return "", errors.New("crypt5 body is too short")
	}

	if err := loadKeys(); err != nil {
		return "", err
	}
	encodedPrivateKey, ok := crypt5Keys[marker]
	if !ok {
		return "", fmt.Errorf("unknown crypt5 key marker: %s", marker)
	}
	key, err := loadPrivateKey(encodedPrivateKey)
	if err != nil {
		return "", err
	}

	// Two known layouts: legacy (segment length right after the 12-byte
	// nonce) and salted (2 skipped bytes + 8-byte salt, then the length).
	// Newer Happ releases use the salted layout, where body[12] is not a
	// digit. Try the preferred one first, then fall back to the other.
	preferSalted := len(body) > 12 && !(body[12] >= '0' && body[12] <= '9')
	var firstErr error
	for _, salted := range [2]bool{preferSalted, !preferSalted} {
		var salt []byte
		if salted {
			salt = []byte(body[14:22])
		}
		result, err := decryptBody(body, key, salt)
		if err == nil {
			return result, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", firstErr
}

// Decrypt decrypts a happ://crypt link and returns the underlying
// URL/text. Unknown or missing prefixes are treated as crypt5, exactly like
// the reference implementation.
func Decrypt(value string) (string, error) {
	v := strings.TrimSpace(value)
	mode, payload := 4, v
	for _, p := range prefixes {
		if len(v) >= len(p.prefix) && strings.EqualFold(v[:len(p.prefix)], p.prefix) {
			mode, payload = p.mode, v[len(p.prefix):]
			break
		}
	}

	if mode == 4 {
		step2, err := decryptCrypt5Middle(m4831f(payload))
		if err != nil {
			return "", err
		}
		decoded, err := b64Decode(m4842j(step2))
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}

	if err := loadKeys(); err != nil {
		return "", err
	}
	if mode >= len(nativeKeys) {
		return "", errors.New("invalid input prefix")
	}
	return decryptRSA(payload, nativeKeys[mode])
}
