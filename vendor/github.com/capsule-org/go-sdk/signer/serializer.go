// Helpers taken from https://danielwiese.com/posts/react-native-gomobile/

package signer

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/capsule-org/go-sdk/internal/network"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/protocols/cmp"
	"github.com/fxamacker/cbor/v2"
)

func SignerParamsFromStr(signerParamsStr string) (*SerializableSigner, error) {
	var signerParams SerializableSigner
	err := json.Unmarshal([]byte(signerParamsStr), &signerParams)
	if err != nil {
		return nil, err
	}

	return &signerParams, nil
}

// Flattened Signer that's gone through KEYGEN
type SerializableSigner struct {
	WalletId  string   `json:WalletId`
	Id        string   `json:Id`
	Ids       []string `json:Ids`
	Threshold int      `json:Threshold`
	Signers   []string `json:Signers`
	Config    string   `json:Config`
	n         *network.Network
	pl        *pool.Pool
}

func SerializeSigner(s Signer) (string, error) {
	is := new(SerializableSigner)
	is.WalletId = s.walletId
	is.Id = string(s.id)
	is.Threshold = s.threshold

	is.Ids = make([]string, len(s.ids))
	for i, e := range s.ids {
		is.Ids[i] = string(e)
	}

	is.Signers = make([]string, len(s.signers))
	for i, e := range s.signers {
		is.Signers[i] = string(e)
	}

	serializedConfig, err := cbor.Marshal(s.config)
	if err != nil {
		return "", err
	}
	is.Config = b64.StdEncoding.EncodeToString(serializedConfig)

	serializedSigner, err := json.Marshal(is)
	if err != nil {
		return "", err
	}
	return string(serializedSigner), nil
}

func DeserializeSigner(signerParamsStr string, serverUrl string) (*Signer, error) {
	var signerParams SerializableSigner
	err := json.Unmarshal([]byte(signerParamsStr), &signerParams)
	if err != nil {
		return nil, err
	}
	return deserializeSigner(signerParams, serverUrl)
}

func deserializeSigner(s SerializableSigner, serverUrl string) (*Signer, error) {
	if len(s.Ids) <= s.Threshold {
		return nil, fmt.Errorf("Threshold (%d) is larger than Ids count (%d)", s.Threshold, len(s.Ids))
	}
	signer := new(Signer)
	signer.id = party.ID(s.Id)
	signer.threshold = s.Threshold
	signer.walletId = s.WalletId

	idSlice := make(party.IDSlice, 0, len(s.Ids))
	for _, e := range s.Ids {
		idSlice = append(idSlice, party.ID(e))
	}
	signer.ids = idSlice
	signer.signers = idSlice[:s.Threshold+1]

	// s.Config will be unintialized during Keygen operation
	if s.Config != "" {
		signer.config = cmp.EmptyConfig(curve.Secp256k1{})
		b64Config, _ := b64.StdEncoding.DecodeString(string(s.Config))
		if err := cbor.Unmarshal(b64Config, signer.config); err != nil {
			return nil, err
		}
	}

	signer.n = network.NewNetwork(s.Ids, serverUrl, nil)

	return signer, nil
}
