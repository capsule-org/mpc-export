package hash

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/capsule-org/multi-party-sig/internal/params"
	"github.com/zeebo/blake3"
)

const DigestLengthBytes = params.SecBytes * 2 // 64

// Hash is the hash function we use for generating commitments, consuming CMP types, etc.
//
// Internally, this is a wrapper around sha3.ShakeHash, but any hash function with
// an easily extendable output would work as well.
type Hash struct {
	h *blake3.Hasher
}

// New creates a Hash struct where the internal hash function is initialized with "CMP-BLAKE".
func New(initialData ...WriterToWithDomain) *Hash {
	hash := &Hash{h: blake3.New()}
	_, _ = hash.h.WriteString("CMP-BLAKE")
	for _, d := range initialData {
		_ = hash.WriteAny(d)
	}
	return hash
}

// Digest returns a reader for the current output of the function.
//
// This finalizes the current state of the hash, and returns what's
// essentially a stream of random bytes.
func (hash *Hash) Digest() io.Reader {
	return hash.h.Digest()
}

// Sum returns a slice of length DigestLengthBytes resulting from the current hash state.
// If a different length is required, use io.ReadFull(hash.Digest(), out) instead.
func (hash *Hash) Sum() []byte {
	out := make([]byte, DigestLengthBytes)
	if _, err := io.ReadFull(hash.Digest(), out); err != nil {
		panic(fmt.Sprintf("hash.ReadBytes: internal hash failure: %v", err))
	}
	return out
}

// WriteAny takes many different data types and writes them to the hash state.
//
// Currently supported types:
//
//   - []byte
//   - *saferith.Nat
//   - *saferith.Int
//   - *saferith.Modulus
//   - hash.WriterToWithDomain
//
// This function will apply its own domain separation for the first two types.
// The last type already suggests which domain to use, and this function respects it.
func (hash *Hash) WriteAny(data ...interface{}) error {
	var sizeBuf [8]byte
	var toBeWritten BytesWithDomain
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			if t == nil {
				return errors.New("hash.WriteAny: nil []byte")
			}
			toBeWritten = BytesWithDomain{"[]byte", t}
		case *big.Int:
			if t == nil {
				return fmt.Errorf("hash.WriteAny: write *big.Int: nil")
			}
			bytes, _ := t.GobEncode()
			toBeWritten = BytesWithDomain{"big.Int", bytes}
		case WriterToWithDomain:
			var buf = new(bytes.Buffer)
			_, err := t.WriteTo(buf)
			if err != nil {
				name := reflect.TypeOf(t)
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}
			toBeWritten = BytesWithDomain{t.Domain(), buf.Bytes()}
		case encoding.BinaryMarshaler:
			name := reflect.TypeOf(t)
			bytes, err := t.MarshalBinary()
			if err != nil {
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}
			toBeWritten = BytesWithDomain{
				TheDomain: name.String(),
				Bytes:     bytes,
			}
		default:
			// This should panic or something
			return fmt.Errorf("hash.WriteAny: invalid type provided as input")
		}

		// Write out `(<domain_size><domain><data_size><data>)`, so that each domain separated piece of data
		// is distinguished from others.

		// (
		_, _ = hash.h.WriteString("(")
		// <domain_size>
		binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(toBeWritten.TheDomain)))
		_, _ = hash.h.Write(sizeBuf[:])
		// <domain>
		_, _ = hash.h.WriteString(toBeWritten.TheDomain)
		// <data_size>
		binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(toBeWritten.Bytes)))
		_, _ = hash.h.Write(sizeBuf[:])
		// <data>
		_, _ = hash.h.Write(toBeWritten.Bytes)
		// )
		_, _ = hash.h.WriteString(")")

	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}

// Fork clones this hash, and then writes some data.
func (hash *Hash) Fork(data ...interface{}) *Hash {
	newHash := hash.Clone()
	_ = newHash.WriteAny(data...)
	return newHash
}
