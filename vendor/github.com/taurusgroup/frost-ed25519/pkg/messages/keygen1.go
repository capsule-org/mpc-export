package messages

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/zk"
)

type KeyGen1 struct {
	Proof       *zk.Schnorr
	Commitments *polynomial.Exponent
}

func NewKeyGen1(from party.ID, proof *zk.Schnorr, commitments *polynomial.Exponent) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeKeyGen1,
			From: from,
		},
		KeyGen1: &KeyGen1{
			Proof:       proof,
			Commitments: commitments,
		},
	}
}

func (m *KeyGen1) BytesAppend(existing []byte) ([]byte, error) {
	var err error
	existing, err = m.Proof.BytesAppend(existing)
	if err != nil {
		return nil, err
	}
	existing, err = m.Commitments.BytesAppend(existing)
	if err != nil {
		return nil, err
	}
	return existing, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *KeyGen1) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *KeyGen1) UnmarshalBinary(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("msg1: %w", ErrInvalidMessage)
	}

	m.Proof = &zk.Schnorr{}
	m.Commitments = &polynomial.Exponent{}

	if err := m.Proof.UnmarshalBinary(data[:64]); err != nil {
		return err
	}
	if err := m.Commitments.UnmarshalBinary(data[64:]); err != nil {
		return err
	}

	return nil
}

func (m *KeyGen1) Size() int {
	return m.Proof.Size() + m.Commitments.Size()
}

func (m *KeyGen1) Equal(other interface{}) bool {
	otherMsg, ok := other.(*KeyGen1)
	if !ok {
		return false
	}
	if !otherMsg.Proof.Equal(m.Proof) {
		return false
	}
	if !otherMsg.Commitments.Equal(m.Commitments) {
		return false
	}
	return true
}
