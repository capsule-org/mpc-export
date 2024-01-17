package signer

import (
	// "encoding/hex"

	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/capsule-org/go-sdk/internal/network"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/ethereum/go-ethereum/core/types"
)

func newSignerFromConfig(config string, serverUrl string) (*Signer, error) {
	params := SignerParamsFromStr(config)
	return newSignerFromSerial(params, serverUrl)
}

func newSignerFromSerial(p SerializableSigner, serverUrl string) (*Signer, error) {
	s := new(Signer)
	s.id = party.ID(p.Id)
	idSlice := make(party.IDSlice, 0, len(p.Ids))

	for _, e := range p.Ids {
		idSlice = append(idSlice, party.ID(e))
	}
	s.ids = idSlice
	s.threshold = p.Threshold

	s.n = network.NewNetwork(p.Ids, serverUrl, nil)
	s.pl = nil // pl
	if len(idSlice) <= p.Threshold {
		return nil, fmt.Errorf("Threshold (%d) is larger than Ids count (%d)", p.Threshold, len(idSlice))
	}
	s.signers = idSlice[:p.Threshold+1]
	s.walletId = p.WalletId
	return s, nil
}

func GetAddress(serializedSigner string) string {
	s, err := DeserializeSigner(serializedSigner, "")
	if err != nil {
		return ""
	}
	address, err := s.GetAddress()
	if err != nil {
		return ""
	}
	return address
}

// func GetWalletId(config string) string {
// 	s, _ := newSignerFromConfig(config)
// 	return s.walletId
// }

// func GetConfig(config string) []byte {
// 	s, _ := newSignerFromConfig(config)
// 	if s.config == nil {
// 		return nil
// 	}
// 	data, _ := json.Marshal(s.config)
// 	return data
// }

func CreateAccount(serverUrl string, serializedSigner string, protocolId string) string {
	s, err := DeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	err = s.CreateAccount(protocolId, false)
	if err != nil {
		return err.Error()
	}

	if s.config == nil {
		return "Error: Missing config"
	}
	return SerializeSigner(*s)
}

func Refresh(serverUrl string, serializedSigner string, protocolId string) string {
	s, err := DeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	err = s.RefreshAccount(protocolId, false)
	if err != nil {
		return err.Error()
	}

	return SerializeSigner(*s)
}

/**
* Retrieve a session token for the account
**/
func UnlockAccount(config, r1Signature string) error {
	// TODO: Retrieve session token from the server
	return nil
}

// func RefreshAccount(config, protocolId string) error {
// 	s, _ := newSignerFromConfig(config)
// 	refreshConfig, err := core.Refresh(s.config, s.n, s.pl, protocolId)
// 	if err != nil {
// 		return err
// 	}
// 	s.config = refreshConfig
// 	return nil
// }

func enforceLowSValue(s curve.Scalar) curve.Scalar {
	if s.IsOverHalfOrder() {
		return s.Negate()
	}
	return s
}

func TransactionBase64ToBytes(tx string) ([]byte, error) {
	messageBytes, err := base64.StdEncoding.DecodeString(tx)
	if err != nil {
		return nil, err
	}
	return messageBytes, nil
}

/**
* Sign message
* @param message - The message encoded in base64
*                      (base64 is easier to decode in native)
 */
func SignMessage(serverUrl, serializedSigner, message, protocolId string) string {
	s, err := DeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	messageBytes, err := TransactionBase64ToBytes(message)
	if err != nil {
		return err.Error()
	}

	signature, err := s.SendTransaction(messageBytes, protocolId, false)
	if err != nil {
		return err.Error()
	}

	rawTxSig, err := signature.SigEthereum()
	if err != nil {
		return err.Error()
	}

	return "0x" + hex.EncodeToString(rawTxSig)
}

/**
* Sign a RLP-encoded transaction
* @param txRLPBase64 - The RLP encoded transaction in base64
*                      (base64 is easier to decode in native)
 */
func SendTransaction(serverUrl string, serializedSigner string, txRLPBase64, protocolId string) string {
	s, err := DeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	txBytes, err := TransactionBase64ToBytes(txRLPBase64)
	if err != nil {
		return err.Error()
	}

	tx := &types.Transaction{}
	err = tx.UnmarshalBinary(txBytes)
	if err != nil {
		return err.Error()
	}

	txSigner := types.NewLondonSigner(tx.ChainId())
	txToSend := txSigner.Hash(tx)

	signature, err := s.SendTransaction(txToSend[:], protocolId, false)
	if err != nil {
		return err.Error()
	}

	rawTxSig, err := signature.SigEthereum()
	if err != nil {
		return err.Error()
	}

	return "0x" + hex.EncodeToString(rawTxSig)
}

func DKLSGetAddress(serializedSigner string) string {
	s, err := DKLSDeserializeSigner(serializedSigner, "")
	if err != nil {
		return ""
	}
	address, err := s.GetAddress()
	if err != nil {
		return ""
	}
	return address
}

func DKLSCreateAccount(serverUrl, serializedSigner, protocolId string) string {
	s, err := DKLSDeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	err = s.CreateAccount(protocolId, true)
	if err != nil {
		return err.Error()
	}

	newSigner, err := DKLSSerializeSigner(*s)
	if err != nil {
		return err.Error()
	}
	return newSigner
}

func DKLSRefresh(serverUrl, serializedSigner, protocolId string) string {
	s, err := DKLSDeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	err = s.RefreshAccount(protocolId, true)
	if err != nil {
		return err.Error()
	}

	newSigner, err := DKLSSerializeSigner(*s)
	if err != nil {
		return err.Error()
	}
	return newSigner
}

/**
* Sign message
* @param message - The message encoded in base64
*                      (base64 is easier to decode in native)
 */
func DKLSSignMessage(serverUrl, serializedSigner, message, protocolId string) string {
	s, err := DKLSDeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	messageBytes, err := TransactionBase64ToBytes(message)
	if err != nil {
		return err.Error()
	}

	signature, err := s.SendTransaction(messageBytes, protocolId, true)
	if err != nil {
		return err.Error()
	}

	rawTxSig, err := signature.SigEthereum()
	if err != nil {
		return err.Error()
	}

	return "0x" + hex.EncodeToString(rawTxSig)
}

/**
* Sign a RLP-encoded transaction
* @param txRLPBase64 - The RLP encoded transaction in base64
*                      (base64 is easier to decode in native)
 */
func DKLSSendTransaction(serverUrl, serializedSigner, txRLPBase64, protocolId string) string {
	s, err := DKLSDeserializeSigner(serializedSigner, serverUrl)
	if err != nil {
		return err.Error()
	}

	txBytes, err := TransactionBase64ToBytes(txRLPBase64)
	if err != nil {
		return err.Error()
	}

	tx := &types.Transaction{}
	err = tx.UnmarshalBinary(txBytes)
	if err != nil {
		return err.Error()
	}

	txSigner := types.NewLondonSigner(tx.ChainId())
	txToSend := txSigner.Hash(tx)

	signature, err := s.SendTransaction(txToSend[:], protocolId, true)
	if err != nil {
		return err.Error()
	}

	rawTxSig, err := signature.SigEthereum()
	if err != nil {
		return err.Error()
	}

	return "0x" + hex.EncodeToString(rawTxSig)
}

/**
* Sign arbitrary hash
* @param hashHex - input to sign encoded as a hex string
* @param signer - Address of the signer (must be unlocked)
 */
func SignHash(config string) {

}

/**
* Decrypts an ECIES ciphertext
* @param account - the address of the account
* @param ciphertext - the cipher to be decrypted
* @returns the decrypted text
 */
func Decrypt(config string) {

}

/**
* Computes an ECDH shared secret between the user's private key and another user's public key
* @param account - the address of the account
* @param publicKey - another user's public key in base64
* @returns the shared secret
 */
func ComputeSharedSecret(config string) {

}
