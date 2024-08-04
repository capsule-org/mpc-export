package zk

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"

	"crypto/sha512"
)

// Schnorr is a Non-Interactive Zero-Knowledge proof of knowledge of
// the discrete logarithm of public = [secret] B
//
// The public parameters are:
//   partyID: prover's uint32 ID
//   context: 32 byte context string,
//   public:  [secret] B
//
type Schnorr struct {
	// S = H( ID || CTX || public || M )
	// R = k + secret • s
	S, R ristretto.Scalar
}

// NewSchnorrProof computes a NIZK proof of knowledge of discrete.
//    partyID is the uint32 ID of the prover
//    public is the point [private]•B
//    context is a 32 byte context (if it is set to [0 ... 0] then we may be susceptible to replay attacks)
//    private is the discrete log of public
//
// We sample a random Scalar k, and obtain M = [k]•B
// S := H(ID,CTX,Public,M)
// R := k + private•S
//
// The proof returned is the tuple (S,R)
func NewSchnorrProof(partyID party.ID, public *ristretto.Element, context []byte, private *ristretto.Scalar) *Schnorr {
	var proof Schnorr

	// Compute commitment for random nonce
	k := scalar.NewScalarRandom()

	// M = [k] B
	var M ristretto.Element
	M.ScalarBaseMult(k)

	S := challenge(partyID, context, public, &M)
	proof.S.Set(S)
	proof.R.MultiplyAdd(private, S, k)

	return &proof
}

// Verify verifies that the zero knowledge proof is valid.
//    partyID is the uint32 ID of the prover
//    public is the point [private]•B
//    context is a 32 byte context (if it is set to [0 ... 0] then we may be susceptible to replay attacks)
func (proof *Schnorr) Verify(partyID party.ID, public *ristretto.Element, context []byte) bool {
	var MPrime, publicNeg ristretto.Element

	publicNeg.Negate(public)

	MPrime.VarTimeDoubleScalarBaseMult(&proof.S, &publicNeg, &proof.R)

	SPrime := challenge(partyID, context, public, &MPrime)

	return proof.S.Equal(SPrime) == 1
}

// challenge computes the hash H(partyID, context, public, M), where
//   partyID: prover's uint32 ID
//   context: 32 byte context string,
//   public:  [secret] B
//   M:       [k] B
func challenge(partyID party.ID, context []byte, public, M *ristretto.Element) *ristretto.Scalar {
	// S = H( ID || CTX || Public || M )
	var S ristretto.Scalar

	h := sha512.New()
	_, _ = h.Write(partyID.Bytes())
	_, _ = h.Write(context[:32])
	_, _ = h.Write(public.Bytes())
	_, _ = h.Write(M.Bytes())

	buffer := make([]byte, 64)
	// SetUniformBytes only returns an error when the length is wrong so we're okay here
	_, _ = S.SetUniformBytes(h.Sum(buffer))
	return &S
}

//
// FROSTMarshaler
//

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (proof *Schnorr) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, 64)
	return proof.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (proof *Schnorr) UnmarshalBinary(data []byte) error {
	if len(data) < 64 {
		return errors.New("length is wrong")
	}
	var err error
	_, err = proof.S.SetCanonicalBytes(data[:32])
	if err != nil {
		return err
	}
	_, err = proof.R.SetCanonicalBytes(data[32:])
	if err != nil {
		return err
	}
	return nil
}

func (proof *Schnorr) BytesAppend(existing []byte) (data []byte, err error) {
	existing = append(existing, proof.S.Bytes()...)
	existing = append(existing, proof.R.Bytes()...)
	return existing, nil
}

func (proof *Schnorr) Size() int {
	return 64
}

func (proof *Schnorr) Equal(other interface{}) bool {
	otherProof, ok := other.(*Schnorr)
	if !ok {
		return false
	}
	if otherProof.S.Equal(&proof.S) != 1 {
		return false
	}
	if otherProof.R.Equal(&proof.R) != 1 {
		return false
	}
	return true
}
