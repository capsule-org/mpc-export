package messages

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const sizeSign1 = 32 + 32

type Sign1 struct {
	// Di = [di] B
	// Ei = [ei] B
	Di, Ei ristretto.Element
}

func NewSign1(from party.ID, commitmentD, commitmentE *ristretto.Element) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeSign1,
			From: from,
		},
		Sign1: &Sign1{
			Di: *commitmentD,
			Ei: *commitmentE,
		},
	}
}

func (m *Sign1) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, m.Di.Bytes()...)
	existing = append(existing, m.Ei.Bytes()...)
	return existing, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Sign1) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, sizeSign1)
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Sign1) UnmarshalBinary(data []byte) error {
	var err error

	if len(data) != sizeSign1 {
		return fmt.Errorf("msg1: %w", ErrInvalidMessage)
	}

	_, err = m.Di.SetCanonicalBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg1.D: %w", err)
	}

	_, err = m.Ei.SetCanonicalBytes(data[32:])
	if err != nil {
		return fmt.Errorf("msg1.E: %w", err)
	}

	return nil
}

func (m *Sign1) Size() int {
	return sizeSign1
}

func (m *Sign1) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Sign1)
	if !ok {
		return false
	}
	if otherMsg.Di.Equal(&m.Di) != 1 {
		return false
	}
	if otherMsg.Ei.Equal(&m.Ei) != 1 {
		return false
	}
	return true
}
