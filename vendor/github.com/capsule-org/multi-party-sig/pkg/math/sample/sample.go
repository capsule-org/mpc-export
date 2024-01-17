package sample

import (
	"fmt"
	"io"
	"math/big"

	"github.com/capsule-org/multi-party-sig/internal/params"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/cronokirby/saferith"
)

const maxIterations = 255

var ErrMaxIterations = fmt.Errorf("sample: failed to generate after %d iterations", maxIterations)

func mustReadBits(rand io.Reader, buf []byte) {
	for i := 0; i < maxIterations; i++ {
		if _, err := io.ReadFull(rand, buf); err == nil {
			return
		}
	}
	panic(ErrMaxIterations)
}

// ModN samples an element of ℤₙ.
func ModN(rand io.Reader, n *saferith.Modulus) *saferith.Nat {
	out := new(saferith.Nat)
	buf := make([]byte, (n.BitLen()+7)/8)
	n = saferith.ModulusFromNat(n.Nat())
	for {
		mustReadBits(rand, buf)
		out.SetBytes(buf)
		_, _, lt := out.CmpMod(n)
		if lt == 1 {
			break
		}
	}
	return out
}

// UnitModN returns a u ∈ ℤₙˣ.
func UnitModN(rand io.Reader, n *saferith.Modulus) *saferith.Nat {
	out := new(saferith.Nat)
	buf := make([]byte, (n.BitLen()+7)/8)
	n = saferith.ModulusFromNat(n.Nat())
	for i := 0; i < maxIterations; i++ {
		// PERF: Reuse buffer instead of allocating each time
		mustReadBits(rand, buf)
		out.SetBytes(buf)
		if out.IsUnit(n) == 1 {
			return out
		}
	}
	panic(ErrMaxIterations)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(rand io.Reader, n *saferith.Modulus) *saferith.Nat {
	var w big.Int
	nBig := n.Big()
	buf := make([]byte, params.BitsIntModN/8)
	for i := 0; i < maxIterations; i++ {
		mustReadBits(rand, buf)
		w.SetBytes(buf)
		w.Mod(&w, nBig)
		if big.Jacobi(&w, nBig) == -1 {
			return new(saferith.Nat).SetBig(&w, w.BitLen())
		}
	}
	panic(ErrMaxIterations)
}

// Pedersen generates the s, t, λ such that s = tˡ.
func Pedersen(rand io.Reader, phi *saferith.Nat, n *saferith.Modulus) (s, t, lambda *saferith.Nat) {
	phiMod := saferith.ModulusFromNat(phi)

	lambda = ModN(rand, phiMod)

	tau := UnitModN(rand, n)
	// t = τ² mod N
	t = tau.ModMul(tau, tau, n)
	// s = tˡ mod N
	// TODO SPEED
	s = new(saferith.Nat).Exp(t, lambda, n)

	return
}

// Scalar returns a new *curve.Scalar by reading bytes from rand.
func Scalar(rand io.Reader, group curve.Curve) curve.Scalar {
	buffer := make([]byte, group.SafeScalarBytes())
	mustReadBits(rand, buffer)
	n := new(saferith.Nat).SetBytes(buffer)
	return group.NewScalar().SetNat(n)
}

// ScalarUnit returns a new *curve.Scalar by reading bytes from rand.
func ScalarUnit(rand io.Reader, group curve.Curve) curve.Scalar {
	for i := 0; i < maxIterations; i++ {
		s := Scalar(rand, group)
		if !s.IsZero() {
			return s
		}
	}
	panic(ErrMaxIterations)
}

// ScalarPointPair returns a new *curve.Scalar/*curve.Point tuple (x,X) by reading bytes from rand.
// The tuple satisfies X = x⋅G where G is the base point of the curve.
func ScalarPointPair(rand io.Reader, group curve.Curve) (curve.Scalar, curve.Point) {
	s := Scalar(rand, group)
	return s, s.ActOnBase()
}
