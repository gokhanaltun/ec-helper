package echelper

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type EcKey struct {
	EcdsaPrivKey *ecdsa.PrivateKey
	EcdhPrivKey  *ecdh.PrivateKey
}

func NewEcKey(privKey *ecdsa.PrivateKey) (*EcKey, error) {
	ecdhPriv, err := ecdhPrivFromEcdsaPriv(privKey)
	if err != nil {
		return nil, err
	}

	return &EcKey{
		EcdsaPrivKey: privKey,
		EcdhPrivKey:  ecdhPriv,
	}, nil
}

func ecdhPrivFromEcdsaPriv(key *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	ecdhPriv, err := key.ECDH()
	if err != nil {
		return nil, err
	}

	return ecdhPriv, nil
}

func (e *EcKey) PrivToPem() (string, error) {
	der, err := x509.MarshalECPrivateKey(e.EcdsaPrivKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}

func FromPrivPem(privPem string) (*EcKey, error) {
	block, _ := pem.Decode([]byte(privPem))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid pem format")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecKey, err := NewEcKey(privKey)
	if err != nil {
		return nil, err
	}

	return ecKey, nil
}

func (e *EcKey) PubToPem() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&e.EcdsaPrivKey.PublicKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func PubFromPem(pubPem string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, errors.New("pem block decode error")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a *ecdsa.PublicKey")
	}

	return ecdsaPubKey, nil
}
