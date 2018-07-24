package btcutil

import (
	"github.com/phoreproject/btcd/chaincfg/chainhash"
	"gitlab.com/nitya-sattva/go-x11/blake"
	"gitlab.com/nitya-sattva/go-x11/bmw"
	"gitlab.com/nitya-sattva/go-x11/groest"
	"gitlab.com/nitya-sattva/go-x11/skein"
	"gitlab.com/nitya-sattva/go-x11/jhash"
	"gitlab.com/nitya-sattva/go-x11/keccak"
	"gitlab.com/nitya-sattva/go-x11/hash"
)

type Hash struct {
	out1 [64]byte
	out2 [64]byte

	blake   hash.Digest
	bmw     hash.Digest
	groest  hash.Digest
	jhash   hash.Digest
	keccak  hash.Digest
	skein   hash.Digest
}

// New returns a new object to compute a x11 hash.
func New() *Hash {
	ref := &Hash{}
	ref.blake = blake.New()
	ref.bmw = bmw.New()
	ref.groest = groest.New()
	ref.jhash = jhash.New()
	ref.keccak = keccak.New()
	ref.skein = skein.New()
	return ref
}

func (ref *Hash) Hash(data []byte) chainhash.Hash {
	out1 := ref.out1[:]
	out2 := ref.out2[:]

	ref.blake.Write(data)
	ref.blake.Close(out1, 0,0)

	ref.bmw.Write(out1)
	ref.bmw.Close(out2, 0, 0)

	if out2[0] & 8 != 0 {
		ref.groest.Write(out2)
		ref.groest.Close(out1, 0, 0)
	} else {
		ref.skein.Write(out2)
		ref.skein.Close(out1, 0, 0)
	}

	ref.groest.Reset()
	ref.groest.Write(out1)
	ref.groest.Close(out2, 0, 0)

	ref.jhash.Write(out2)
	ref.jhash.Close(out1, 0,0)

	if out1[0] & 8 != 0 {
		ref.blake.Reset()
		ref.blake.Write(out1)
		ref.blake.Close(out2, 0,0)
	} else {
		ref.bmw.Reset()
		ref.bmw.Write(out1)
		ref.bmw.Close(out2, 0, 0)
	}

	ref.keccak.Write(out2)
	ref.keccak.Close(out1, 0,0)

	ref.skein.Reset()
	ref.skein.Write(out1)
	ref.skein.Close(out2, 0,0)

	if out2[0] & 8 != 0 {
		ref.keccak.Reset()
		ref.keccak.Write(out2)
		ref.keccak.Close(out1, 0,0)
	} else {
		ref.jhash.Reset()
		ref.jhash.Write(out2)
		ref.jhash.Close(out1, 0,0)
	}

	var out [32]byte

	copy(out[:], out1)

	return chainhash.Hash(out)
}