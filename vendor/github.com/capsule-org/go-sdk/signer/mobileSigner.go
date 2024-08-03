package signer

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/core/types"
)

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
	newSigner, err := SerializeSigner(*s)
	if err != nil {
		return err.Error()
	}
	return newSigner
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

	newSigner, err := SerializeSigner(*s)
	if err != nil {
		return err.Error()
	}
	return newSigner
}

/**
* Retrieve a session token for the account
**/
func UnlockAccount(config, r1Signature string) error {
	// TODO: Retrieve session token from the server
	return nil
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

func ED25519CreateAccount(mpcNetworkWSHost, walletId, protocolId string) string {
	userSigner := ED25519NewSigner(mpcNetworkWSHost, walletId, ED25519UserPartyId, ED25519CapsulePartyId, nil)
	err := userSigner.CreateAccount(protocolId)
	if err != nil {
		return err.Error()
	}

	newSigner, err := ED25519SerializeSigner(userSigner)
	if err != nil {
		return err.Error()
	}
	return newSigner
}

/**
* Sign
* @param message - The bytes to sign encoded in base64
*                      (base64 is easier to decode in native)
 */
func ED25519Sign(serializedSigner, base64BytesToSign, protocolId string) string {
	s, err := ED25519DeserializeSigner(serializedSigner)
	if err != nil {
		return err.Error()
	}

	bytesToSign, err := TransactionBase64ToBytes(base64BytesToSign)
	if err != nil {
		return err.Error()
	}

	signature, err := s.Sign(protocolId, bytesToSign)
	if err != nil {
		return err.Error()
	}

	return base64.StdEncoding.EncodeToString(signature.ToEd25519())
}
