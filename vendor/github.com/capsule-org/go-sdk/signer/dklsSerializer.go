package signer

import (
	b64 "encoding/base64"
	"encoding/json"

	"github.com/capsule-org/go-sdk/internal/network"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/protocols/doerner"
	"github.com/fxamacker/cbor/v2"
)

func DKLSSignerParamsFromStr(signerParamsStr string) (SerializableSigner, error) {
	var signerParams SerializableSigner
	err := json.Unmarshal([]byte(signerParamsStr), &signerParams)
	return signerParams, err
}

// Flattened Signer that's gone through KEYGEN
type DKLSSerializableSigner struct {
	WalletId          string `json:"walletId"`
	Id                string `json:"id"`
	OtherId           string `json:"otherId"`
	ReceiverConfig    string `json:"receiverConfig"`
	SenderConfig      string `json:"senderConfig"`
	IsReceiver        bool   `json:"isReceiver"`
	DisableWebSockets bool   `json:"disableWebSockets"`
	n                 *network.Network
	pl                *pool.Pool
}

func DKLSSerializeSigner(s DKLSSigner) (string, error) {
	is := new(DKLSSerializableSigner)
	is.WalletId = s.walletId
	is.Id = string(s.id)
	is.OtherId = string(s.otherId)
	is.IsReceiver = s.isReceiver
	is.DisableWebSockets = s.disableWebSockets

	serializedReceiverConfig, err := cbor.Marshal(s.receiverConfig)
	if err != nil {
		return "", err
	}
	is.ReceiverConfig = b64.StdEncoding.EncodeToString(serializedReceiverConfig)

	serializedSenderConfig, err := cbor.Marshal(s.senderConfig)
	if err != nil {
		return "", err
	}
	is.SenderConfig = b64.StdEncoding.EncodeToString(serializedSenderConfig)

	serializedSigner, err := json.Marshal(is)
	if err != nil {
		return "", err
	}
	return string(serializedSigner), nil
}

func DKLSDeserializeSigner(signerParamsStr string, serverUrl string) (*DKLSSigner, error) {
	var signerParams DKLSSerializableSigner
	err := json.Unmarshal([]byte(signerParamsStr), &signerParams)
	if err != nil {
		return nil, err
	}
	return dklsDeserializeSigner(signerParams, serverUrl)
}

func dklsDeserializeSigner(s DKLSSerializableSigner, serverUrl string) (*DKLSSigner, error) {
	signer := new(DKLSSigner)
	signer.id = party.ID(s.Id)
	signer.walletId = s.WalletId
	signer.otherId = party.ID(s.OtherId)
	signer.isReceiver = s.IsReceiver
	signer.disableWebSockets = s.DisableWebSockets

	if s.IsReceiver && s.ReceiverConfig != "" {
		signer.receiverConfig = doerner.EmptyConfigReceiver(curve.Secp256k1{})
		b64Config, err := b64.StdEncoding.DecodeString(string(s.ReceiverConfig))
		if err != nil {
			return nil, err
		}
		if err := cbor.Unmarshal(b64Config, signer.receiverConfig); err != nil {
			return nil, err
		}
	} else if !s.IsReceiver && s.SenderConfig != "" {
		signer.senderConfig = doerner.EmptyConfigSender(curve.Secp256k1{})
		b64Config, err := b64.StdEncoding.DecodeString(string(s.SenderConfig))
		if err != nil {
			return nil, err
		}
		if err := cbor.Unmarshal(b64Config, signer.senderConfig); err != nil {
			return nil, err
		}
	}

	signer.n = network.NewNetwork([]string{s.Id, s.OtherId}, serverUrl, nil)

	return signer, nil
}
