package signer

import (
	"encoding/base64"
	"encoding/json"
)

func ED25519SerializeSigner(s *ED25519Signer) (string, error) {
	signerBytes, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signerBytes), nil
}

func ED25519DeserializeSigner(serializedSigner string) (*ED25519Signer, error) {
	var s ED25519Signer
	signerBytes, err := base64.StdEncoding.DecodeString(serializedSigner)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(signerBytes, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
