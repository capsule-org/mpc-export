package signer

import (
	"github.com/capsule-org/go-sdk/internal/ed25519/communication"
	"github.com/mr-tron/base58"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

type ED25519Signer struct {
	Id       party.ID
	OtherId  party.ID
	Output   *keygen.Output
	WalletId string
	Host     string
}

const (
	ED25519UserPartyId    = party.ID(1) // party.ID(1) will reference the user key
	ED25519CapsulePartyId = party.ID(2) // party.ID(2) will reference the Capsule key
	threshold             = party.ID(1)
)

var PARTY_IDS = party.NewIDSlice([]party.ID{ED25519UserPartyId, ED25519CapsulePartyId})

func ED25519NewSigner(host, walletId string, id, otherId party.ID, keygenOutput *keygen.Output) *ED25519Signer {
	return &ED25519Signer{
		Output:   keygenOutput,
		Host:     host,
		WalletId: walletId,
		Id:       id,
		OtherId:  otherId,
	}
}

func (s *ED25519Signer) GetAddress() string {
	pk := s.Output.Public.GroupKey
	publicKey := pk.ToEd25519()
	return base58.Encode(publicKey)
}

func (s *ED25519Signer) CreateAccount(protocolId string) error {
	c := communication.NewCapsuleCommunicator(s.Host, protocolId, s.Id, s.OtherId, s.Id != ED25519CapsulePartyId)
	err := c.Start(protocolId)
	if err != nil {
		return err
	}

	keygenHandler, err := communication.NewKeyGenHandler(c, s.Id, PARTY_IDS, threshold)
	if err != nil {
		return err
	}
	err = keygenHandler.State.WaitForError()
	if err != nil {
		return err
	}
	c.Done()

	s.Output = keygenHandler.Out
	return nil
}

func (s *ED25519Signer) Sign(protocolId string, bytesToSign []byte) (*eddsa.Signature, error) {
	c := communication.NewCapsuleCommunicator(s.Host, protocolId, s.Id, s.OtherId, s.Id != ED25519CapsulePartyId)
	err := c.Start(protocolId)
	if err != nil {
		return nil, err
	}

	signHandler, err := communication.NewSignHandler(c, PARTY_IDS, s.Output.SecretKey, s.Output.Public, bytesToSign)
	if err != nil {
		return nil, err
	}
	err = signHandler.State.WaitForError()
	if err != nil {
		return nil, err
	}
	c.Done()

	return signHandler.Out.Signature, nil
}
