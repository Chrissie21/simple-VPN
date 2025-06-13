package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadPublicKey loads an RSA public key from a PEM file.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// try PKCS1 public key parsing
		pub1, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, err
		}
		return pub1, nil
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return pub, nil
}

// SignData signs the given data using RSA SHA-256 and returns the signature bytes.
func SignData(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// VerifySignature verifies the RSA SHA-256 signature for the given data.
func VerifySignature(pub *rsa.PublicKey, data []byte, sig []byte) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
}
