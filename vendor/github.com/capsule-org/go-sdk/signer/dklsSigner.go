package signer

import (
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/capsule-org/go-sdk/internal/core"
	"github.com/capsule-org/go-sdk/internal/network"
	"github.com/fxamacker/cbor/v2"

	"github.com/capsule-org/multi-party-sig/pkg/ecdsa"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/protocols/doerner"
	"github.com/wealdtech/go-merkletree/keccak256"
)

type DKLSSigner struct {
	receiverConfig    *doerner.ConfigReceiver // only set if isReceiver false
	senderConfig      *doerner.ConfigSender   // only set if isReceiver true
	id                party.ID
	otherId           party.ID
	n                 *network.Network
	pl                *pool.Pool
	walletId          string
	isReceiver        bool
	disableWebSockets bool
}

func NewDKLSSigner(host, walletId, id, otherId string, pl *pool.Pool, receiverConfig *doerner.ConfigReceiver, senderConfig *doerner.ConfigSender, isReceiver bool, headers map[string]string) DKLSSigner {
	s := new(DKLSSigner)
	s.id = party.ID(id)
	s.otherId = party.ID(otherId)
	s.n = network.NewNetwork([]string{id, otherId}, host, headers)
	s.pl = pl
	s.walletId = walletId
	s.receiverConfig = receiverConfig
	s.senderConfig = senderConfig
	s.isReceiver = isReceiver
	return *s
}

// TODO:
// move SetNetworkClientTransport, CreateWallet, and CreateProtocol to another package in this library long-term
// just here for easier exporting right now
func DKLSCreateWallet(networkHost, walletId string, parties []string, headers map[string]string) {
	network.CreateWallet(networkHost, walletId, parties, headers)
}

func DKLSCreateProtocol(networkHost, walletId string, protocol string, headers map[string]string) string {
	return network.CreateProtocol(networkHost, walletId, protocol, headers)
}

func DKLSSetNetworkClientTransport(transport *http.Transport) {
	network.SetNetworkClientTransport(transport)
}

func (s *DKLSSigner) GetReceiverConfig() ([]byte, error) {
	if s.receiverConfig == nil {
		return nil, fmt.Errorf("cannot get receiver config from sender")
	}
	return cbor.Marshal(s.receiverConfig)
}

func (s *DKLSSigner) GetSenderConfig() ([]byte, error) {
	if s.senderConfig == nil {
		return nil, fmt.Errorf("cannot get sender config from sender")
	}
	return cbor.Marshal(s.senderConfig)
}

func (s *DKLSSigner) GetReceiverConfigStruct() *doerner.ConfigReceiver {
	return s.receiverConfig
}

func (s *DKLSSigner) GetSenderConfigStruct() *doerner.ConfigSender {
	return s.senderConfig
}

func (s *DKLSSigner) SetPool(pl *pool.Pool) {
	s.pl = pl
}

func (s *DKLSSigner) GetPublicKey() string {
	var publicPoint curve.Point
	if s.isReceiver {
		publicPoint = s.receiverConfig.Public
	} else {
		publicPoint = s.senderConfig.Public
	}

	xbytes := publicPoint.(*curve.Secp256k1Point).XBytes()
	ybytes := publicPoint.(*curve.Secp256k1Point).YBytes()
	rawPKey := append(xbytes[:], ybytes[:]...)

	return "0x04" + hex.EncodeToString(rawPKey)
}

func (s *DKLSSigner) GetPrivateKey() curve.Scalar {
	var privateKey curve.Scalar
	if s.isReceiver {
		privateKey = s.receiverConfig.SecretShare
	} else {
		privateKey = s.senderConfig.SecretShare
	}

	return privateKey
}

func (s *DKLSSigner) GetAddress() (string, error) {
	k := keccak256.New()

	encodedPKey := s.GetPublicKey()
	decodedPKey, err := hex.DecodeString(encodedPKey[4:])
	if err != nil {
		return "", err
	}

	decodedPKeyHash := k.Hash(decodedPKey)
	return "0x" + hex.EncodeToString(decodedPKeyHash[len(decodedPKeyHash)-20:]), nil
}

func (s *DKLSSigner) GetWalletId() string {
	return s.walletId
}

func (s *DKLSSigner) GetPartyId() party.ID {
	return s.id
}

func (s *DKLSSigner) GetOtherId() party.ID {
	return s.otherId
}

func (s *DKLSSigner) GetDisableWebSockets() bool {
	return s.disableWebSockets
}

func (s *DKLSSigner) CreateAccount(protocolId string, useWebSocket bool) error {
	if s.isReceiver {
		config, err := core.DKLSReceiverKeygen(s.id, s.otherId, s.n, s.pl, protocolId, useWebSocket)
		if err != nil {
			return err
		}
		s.receiverConfig = config
		return nil
	}

	config, err := core.DKLSSenderKeygen(s.id, s.otherId, s.n, s.pl, protocolId, useWebSocket)
	if err != nil {
		return err
	}
	s.senderConfig = config
	return nil
}

func (s *DKLSSigner) RefreshAccount(protocolId string, useWebSocket bool) error {
	if s.isReceiver {
		newConfig, err := core.DKLSReceiverRefresh(s.receiverConfig, s.id, s.otherId, s.n, s.pl, protocolId, useWebSocket)
		if err != nil {
			return err
		}
		s.receiverConfig = newConfig
		return nil
	}

	newConfig, err := core.DKLSSenderRefresh(s.senderConfig, s.id, s.otherId, s.n, s.pl, protocolId, useWebSocket)
	if err != nil {
		return err
	}
	s.senderConfig = newConfig
	return nil
}

/**
* Sign and send a RLP-encoded transaction
* @param txHash - The hash of the RLP encoded transaction
 */
func (s *DKLSSigner) SendTransaction(txHash []byte, protocolId string, useWebSocket bool) (*ecdsa.Signature, error) {
	if s.isReceiver {
		return core.DKLSReceiverSign(s.receiverConfig, s.id, s.otherId, txHash, s.n, s.pl, protocolId, useWebSocket)
	}
	return core.DKLSSenderSign(s.senderConfig, s.id, s.otherId, txHash, s.n, s.pl, protocolId, useWebSocket)
}
