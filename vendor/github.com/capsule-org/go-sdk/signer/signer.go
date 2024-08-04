package signer

import (
	"encoding/hex"
	"math/big"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/capsule-org/go-sdk/internal/core"
	"github.com/capsule-org/go-sdk/internal/network"

	"github.com/capsule-org/multi-party-sig/pkg/ecdsa"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/paillier"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/protocols/cmp"
	"github.com/ethereum/go-ethereum/common"
	"github.com/wealdtech/go-merkletree/keccak256"
)

// Source https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction.go
type Transaction struct {
	inner TxData    // Consensus contents of a transaction
	time  time.Time // Time first seen locally (spam avoidance)

	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type TxData interface {
	txType() byte // returns the type ID
	copy() TxData // creates a deep copy and initializes all fields

	chainID() *big.Int
	data() []byte
	gas() uint64
	gasPrice() *big.Int
	gasTipCap() *big.Int
	gasFeeCap() *big.Int
	value() *big.Int
	nonce() uint64
	to() *common.Address

	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(chainID, v, r, s *big.Int)
}

type Signer struct {
	config    *cmp.Config
	id        party.ID
	ids       party.IDSlice
	threshold int
	n         *network.Network
	pl        *pool.Pool
	signers   party.IDSlice
	walletId  string
}

func NewSigner(host, walletId, id string, ids []string, threshold int, pl *pool.Pool, config *cmp.Config, headers map[string]string) Signer {
	s := new(Signer)
	s.id = party.ID(id)
	idSlice := make(party.IDSlice, 0, len(ids))
	for _, e := range ids {
		idSlice = append(idSlice, party.ID(e))
	}
	s.ids = idSlice
	s.threshold = threshold
	s.n = network.NewNetwork(ids, host, headers)
	s.pl = pl
	s.signers = idSlice[:threshold+1]
	s.walletId = walletId
	s.config = config
	return *s
}

// TODO:
// move SetNetworkClientTransport, CreateWallet, and CreateProtocol to another package in this library long-term
// just here for easier exporting right now
func CreateWallet(networkHost, walletId string, parties []string, headers map[string]string) error {
	return network.CreateWallet(networkHost, walletId, parties, headers)
}

func CreateProtocol(networkHost, walletId string, protocol string, headers map[string]string) (string, error) {
	return network.CreateProtocol(networkHost, walletId, protocol, headers)
}

func SetNetworkClientTransport(transport *http.Transport) {
	network.SetNetworkClientTransport(transport)
}

func (s *Signer) SetPool(pl *pool.Pool) {
	s.pl = pl
}

func (s *Signer) GetPublicKey() string {
	xbytes := s.config.PublicPoint().(*curve.Secp256k1Point).XBytes()
	ybytes := s.config.PublicPoint().(*curve.Secp256k1Point).YBytes()
	rawPKey := append(xbytes[:], ybytes[:]...)

	return "0x04" + hex.EncodeToString(rawPKey)
}

func (s *Signer) GetAddress() (string, error) {
	k := keccak256.New()

	xbytes := s.config.PublicPoint().(*curve.Secp256k1Point).XBytes()
	ybytes := s.config.PublicPoint().(*curve.Secp256k1Point).YBytes()
	rawPKey := append(xbytes[:], ybytes[:]...)

	encodedPKey := "04" + hex.EncodeToString(rawPKey)
	decodedPKey, err := hex.DecodeString(encodedPKey[2:])
	if err != nil {
		return "", err
	}

	return "0x" + hex.EncodeToString(k.Hash(decodedPKey)[len(xbytes)-20:]), nil
}

func (s *Signer) GetWalletId() string {
	return s.walletId
}

func (s *Signer) GetPartyId() party.ID {
	return s.id
}

func (s *Signer) GetPartyIds() party.IDSlice {
	return s.ids
}

func (s *Signer) GetThreshold() int {
	return s.threshold
}

func (s *Signer) GetConfig() ([]byte, error) {
	if s.config == nil {
		return nil, nil
	}
	return s.config.MarshalBinary()
}

func (s *Signer) CreateAccountV2(protocolId string, secretKey *paillier.SecretKey, statusFunc network.JSFunc, useWebSocket bool) error {
	keygenConfig, err := core.Keygen(s.id, s.ids, s.threshold, s.n, s.pl, protocolId, secretKey, statusFunc, useWebSocket)
	s.config = keygenConfig
	if err != nil {
		return err
	}
	return nil
}

func (s *Signer) CreateAccount(protocolId string, useWebSocket bool) error {
	keygenConfig, err := core.Keygen(s.id, s.ids, s.threshold, s.n, s.pl, protocolId, nil, nil, useWebSocket)
	s.config = keygenConfig
	if err != nil {
		return err
	}
	return nil
}

/**
* Retrieve a session token for the account
**/
func (s *Signer) UnlockAccount(r1Signature string) error {
	// TODO: Retrieve session token from the server
	return nil
}

func (s *Signer) RefreshAccount(protocolId string, useWebSocket bool) error {
	refreshConfig, err := core.Refresh(s.config, s.n, s.pl, protocolId, useWebSocket)
	if err != nil {
		return err
	}
	s.config = refreshConfig
	return nil
}

/**
* Sign and send a RLP-encoded transaction
* @param txHash - The hash of the RLP encoded transaction
 */
func (s *Signer) SendTransaction(txHash []byte, protocolId string, useWebSocket bool) (*ecdsa.Signature, error) {
	signature, err := core.Sign(s.config, txHash, s.signers, s.n, s.pl, protocolId, useWebSocket)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

/**
* Sign arbitrary hash
* @param hashHex - input to sign encoded as a hex string
* @param signer - Address of the signer (must be unlocked)
 */
func (s *Signer) SignHash() {

}

/**
* Decrypts an ECIES ciphertext
* @param account - the address of the account
* @param ciphertext - the cipher to be decrypted
* @returns the decrypted text
 */
func (s *Signer) Decrypt() {

}

/**
* Computes an ECDH shared secret between the user's private key and another user's public key
* @param account - the address of the account
* @param publicKey - another user's public key in base64
* @returns the shared secret
 */
func (s *Signer) ComputeSharedSecret() {

}
