package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// Sealer implements envelope encryption for channel secrets: every value gets
// a random data key (DEK) that encrypts the JSON config with AES-256-GCM; the
// DEK itself is encrypted with the key encryption key (KEK) derived from
// SECRET_KEY via HKDF. Rotating SECRET_KEY only requires re-wrapping DEKs.
//
// Layout: version(1) | nonceKEK(12) | wrappedDEK(48) | nonce(12) | ciphertext
type Sealer struct{ kek cipher.AEAD }

func NewSealer(secret string) (*Sealer, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte("yourcve"), "channel-config-kek-v1", 32)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &Sealer{kek: aead}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

const sealVersion = 1

func (s *Sealer) Seal(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dek := make([]byte, 32)
	rand.Read(dek)
	n1 := make([]byte, 12)
	rand.Read(n1)
	wrapped := s.kek.Seal(nil, n1, dek, []byte{sealVersion})
	data, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	n2 := make([]byte, 12)
	rand.Read(n2)
	out := []byte{sealVersion}
	out = append(out, n1...)
	out = append(out, wrapped...)
	out = append(out, n2...)
	return data.Seal(out, n2, plain, []byte{sealVersion}), nil
}

func (s *Sealer) Open(b []byte, v any) error {
	if len(b) < 1+12+48+12 || b[0] != sealVersion {
		return errors.New("sealed config: bad format")
	}
	n1, wrapped, n2, ct := b[1:13], b[13:61], b[61:73], b[73:]
	dek, err := s.kek.Open(nil, n1, wrapped, []byte{sealVersion})
	if err != nil {
		return errors.New("sealed config: wrong SECRET_KEY or corrupted data")
	}
	data, err := newGCM(dek)
	if err != nil {
		return err
	}
	plain, err := data.Open(nil, n2, ct, []byte{sealVersion})
	if err != nil {
		return errors.New("sealed config: corrupted data")
	}
	return json.Unmarshal(plain, v)
}
