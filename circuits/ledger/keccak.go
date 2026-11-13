package ledger

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// In-circuit SHAKE-256 with a 32-byte output, over a message whose length is
// fixed at compile time. Bits are frontend.Variables; constant bits stay Go
// ints, so prefixes and padding cost nothing.
//
// The permutation is written bit by bit with plain R1CS gates (no lookup
// tables), so the Groth16 key has no BSB22 commitment: the chain's verifier
// sees a plain four-input Groth16 statement.

const shakeRate = 136 // SHAKE-256 rate in bytes

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakRot[x][y] is the rho rotation offset of lane (x, y).
var keccakRot = [5][5]int{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

type bitAPI struct{ api frontend.API }

func (b bitAPI) konst(v frontend.Variable) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	}
	if c, ok := b.api.Compiler().ConstantValue(v); ok {
		return int(c.Int64()), true
	}
	return 0, false
}

func (b bitAPI) xor(x, y frontend.Variable) frontend.Variable {
	cx, kx := b.konst(x)
	cy, ky := b.konst(y)
	switch {
	case kx && ky:
		return cx ^ cy
	case kx:
		if cx == 0 {
			return y
		}
		return b.api.Sub(1, y)
	case ky:
		if cy == 0 {
			return x
		}
		return b.api.Sub(1, x)
	}
	// x + y - 2xy
	return b.api.Sub(b.api.Add(x, y), b.api.Mul(2, x, y))
}

// andNot returns (NOT x) AND y.
func (b bitAPI) andNot(x, y frontend.Variable) frontend.Variable {
	cx, kx := b.konst(x)
	cy, ky := b.konst(y)
	switch {
	case kx && ky:
		return (1 - cx) & cy
	case kx:
		if cx == 1 {
			return 0
		}
		return y
	case ky:
		if cy == 0 {
			return 0
		}
		return b.api.Sub(1, x)
	}
	return b.api.Sub(y, b.api.Mul(x, y))
}

type lane [64]frontend.Variable

func (b bitAPI) permute(a *[25]lane) {
	for round := 0; round < 24; round++ {
		// theta
		var c [5]lane
		for x := 0; x < 5; x++ {
			for z := 0; z < 64; z++ {
				v := a[x][z]
				for y := 1; y < 5; y++ {
					v = b.xor(v, a[x+5*y][z])
				}
				c[x][z] = v
			}
		}
		for x := 0; x < 5; x++ {
			for z := 0; z < 64; z++ {
				d := b.xor(c[(x+4)%5][z], c[(x+1)%5][(z+63)%64])
				for y := 0; y < 5; y++ {
					a[x+5*y][z] = b.xor(a[x+5*y][z], d)
				}
			}
		}
		// rho and pi: B[y, 2x+3y] = rot(A[x, y], r[x][y])
		var bb [25]lane
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				r := keccakRot[x][y]
				dst := y + 5*((2*x+3*y)%5)
				for z := 0; z < 64; z++ {
					bb[dst][z] = a[x+5*y][(z-r+64)%64]
				}
			}
		}
		// chi
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				for z := 0; z < 64; z++ {
					a[x+5*y][z] = b.xor(bb[x+5*y][z], b.andNot(bb[(x+1)%5+5*y][z], bb[(x+2)%5+5*y][z]))
				}
			}
		}
		// iota
		for z := 0; z < 64; z++ {
			if keccakRC[round]>>z&1 == 1 {
				a[0][z] = b.xor(a[0][z], 1)
			}
		}
	}
}

// shake256x32 hashes msg (a list of bytes, each 8 bits LSB first) and returns
// 32 output bytes as bits, LSB first within each byte.
func (b bitAPI) shake256x32(msg [][8]frontend.Variable) [32][8]frontend.Variable {
	padded := make([][8]frontend.Variable, 0, len(msg)+shakeRate)
	padded = append(padded, msg...)
	padded = append(padded, constByte(0x1F))
	for len(padded)%shakeRate != 0 {
		padded = append(padded, constByte(0))
	}
	last := len(padded) - 1
	padded[last][7] = b.xor(padded[last][7], 1) // final bit 0x80

	var st [25]lane
	for i := range st {
		for z := range st[i] {
			st[i][z] = 0
		}
	}
	for off := 0; off < len(padded); off += shakeRate {
		for i := 0; i < shakeRate; i++ {
			l, byteInLane := i/8, i%8
			for bit := 0; bit < 8; bit++ {
				z := byteInLane*8 + bit
				st[l][z] = b.xor(st[l][z], padded[off+i][bit])
			}
		}
		b.permute(&st)
	}
	var out [32][8]frontend.Variable
	for i := 0; i < 32; i++ {
		for bit := 0; bit < 8; bit++ {
			out[i][bit] = st[i/8][(i%8)*8+bit]
		}
	}
	return out
}

func constByte(v byte) [8]frontend.Variable {
	var out [8]frontend.Variable
	for i := 0; i < 8; i++ {
		out[i] = int(v >> i & 1)
	}
	return out
}

func constBytes(bs []byte) [][8]frontend.Variable {
	out := make([][8]frontend.Variable, len(bs))
	for i, v := range bs {
		out[i] = constByte(v)
	}
	return out
}

// packBE packs 32 bytes (bits LSB first) as a big-endian integer into one field
// element, which reduces it mod r, as the chain does with withdrawals_root.
func (b bitAPI) packBE(bs [32][8]frontend.Variable) frontend.Variable {
	terms := make([]frontend.Variable, 0, 256)
	for i := 0; i < 32; i++ {
		for bit := 0; bit < 8; bit++ {
			pos := (31-i)*8 + bit
			terms = append(terms, b.api.Mul(bs[i][bit], pow2(pos)))
		}
	}
	return b.api.Add(terms[0], terms[1], terms[2:]...)
}

func pow2(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }
