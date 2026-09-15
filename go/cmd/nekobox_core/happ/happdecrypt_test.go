package happdecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// buildRsaLink encrypts msg with the public half of a published private key,
// mirroring the reference test construction (happ-decrypt-universal lib.rs
// make_rsa_link).
func buildRsaLink(t *testing.T, prefix string, key *rsa.PrivateKey, msg string) string {
	t.Helper()
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	return prefix + base64StdEncode(encrypted)
}

// buildCrypt5Link mirrors the reference test construction (lib.rs
// make_crypt5_link).
func buildCrypt5Link(t *testing.T, marker, encodedPrivateKey, msg string) string {
	t.Helper()
	key, err := loadPrivateKey(encodedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	chachaKey := sha256Sum([]byte(marker))
	nonce := []byte(marker + "test")

	finalB64 := base64StdEncode([]byte(msg))
	chachaPlain := m4842j(finalB64)
	encrypted, err := chachaSeal(chachaKey, nonce, []byte(chachaPlain))
	if err != nil {
		t.Fatal(err)
	}
	encryptedSegment := base64StdEncode(encrypted)

	rsaPlain := m4842j(base64StdEncode(chachaKey))
	rsaCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, []byte(rsaPlain))
	if err != nil {
		t.Fatal(err)
	}

	body := string(nonce) + itoa(len(encryptedSegment)) + "f" + encryptedSegment + base64StdEncode(rsaCiphertext)
	shuffled := marker[:4] + body + marker[4:]
	return "happ://crypt5/" + permute4(shuffled)
}

func TestVerifiedVectors(t *testing.T) {
	if len(verifiedVectors) == 0 {
		t.Fatal("no verified vectors embedded")
	}
	for i, v := range verifiedVectors {
		got, err := Decrypt(v.Input)
		if err != nil {
			t.Errorf("vector %d: unexpected error: %v", i, err)
			continue
		}
		if got != v.Expected {
			t.Errorf("vector %d: got %q, want %q", i, got, v.Expected)
		}
	}
}

func TestSyntheticAllKeys(t *testing.T) {
	if err := loadKeys(); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"happ://crypt/", "happ://crypt2/", "happ://crypt3/", "happ://crypt4/"}
	for mode, key := range nativeKeys {
		want := "https://sub.example.com/native-mode" + itoa(mode)
		link := buildRsaLink(t, prefixes[mode], key, want)
		if got, err := Decrypt(link); err != nil || got != want {
			t.Errorf("native mode %d: got %q, %v (want %q)", mode, got, err, want)
		}
		if !IsHappLink(link) {
			t.Errorf("IsHappLink(%s...) = false", link[:20])
		}
	}

	for marker, encodedKey := range crypt5Keys {
		want := "https://sub.example.com/crypt5-" + marker
		link := buildCrypt5Link(t, marker, encodedKey, want)
		if got, err := Decrypt(link); err != nil || got != want {
			t.Errorf("crypt5 marker %s: got %q, %v (want %q)", marker, got, err, want)
		}
	}
}

func TestRoundTripShuffles(t *testing.T) {
	const value = "abcdefghijklmnopqrstuvwxyz0123456789"
	if inverseM4831f(m4831f(value)) != value {
		t.Error("m4831f inverse mismatch")
	}
	if m4842j(m4842j(value)) != value {
		t.Error("m4842j inverse mismatch")
	}
	if permute4(permute4(value)) != value {
		t.Error("permute4 inverse mismatch")
	}
}

func TestInvalidInputs(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"happ://crypt/",
		"happ://crypt/!!!not-base64!!!",
		"happ://crypt/QUJD",              // valid base64, not valid RSA ciphertext
		"happ://crypt5/short",            // too short
		"happ://crypt5/AAAAAAAAAAAAAAAA", // wrong marker path
		"happ://crypt9/QUJD",             // unknown prefix -> crypt5 path -> fails
	}
	for _, s := range bad {
		if got, err := Decrypt(s); err == nil {
			t.Errorf("Decrypt(%q) = %q, want error", s, got)
		}
	}
	if IsHappLink("https://example.com/sub") {
		t.Error("IsHappLink should reject plain urls")
	}
	if !IsHappLink("  HAPP://CRYPT5/abc") {
		t.Error("IsHappLink should accept padded/uppercase happ links")
	}
	if !strings.HasPrefix("happ://crypt/x", "happ://crypt") {
		t.Error("sanity")
	}
}

func TestUppercasePrefix(t *testing.T) {
	v := verifiedVectors[0]
	upper := strings.ToUpper("happ://crypt") + strings.TrimPrefix(v.Input, "happ://crypt")
	got, err := Decrypt(upper)
	if err != nil {
		// prefix folding must at least route to the same mode; payload itself
		// is untouched, so a valid vector must decrypt.
		t.Fatalf("uppercase prefix: unexpected error: %v", err)
	}
	if got != v.Expected {
		t.Fatalf("uppercase prefix: got %q, want %q", got, v.Expected)
	}
}

// terse helpers for the reference test constructions above

func base64StdEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func itoa(n int) string { return strconv.Itoa(n) }

func chachaSeal(key, nonce, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}
