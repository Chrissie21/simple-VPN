package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type VPNCrypto struct {
	gcm cipher.AEAD
}

func NewVPNCrypto(key []byte) (*VPNCrypto, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &VPNCrypto{gcm: gcm}, nil
}

func (v *VPNCrypto) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := v.gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, ciphertext...), nil
}

func (v *VPNCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := v.gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:ns]
	enc := ciphertext[ns:]

	return v.gcm.Open(nil, nonce, enc, nil)
}
