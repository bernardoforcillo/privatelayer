package wireguard

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}, nil
}

func ParsePrivateKey(key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(key)
}

func ParsePublicKey(key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(key)
}
