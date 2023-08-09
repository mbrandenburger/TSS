package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestBLS(t *testing.T) {
	sk := c.NewZrFromInt(2)
	pk := c.GenG2.Copy().Mul(sk)

	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	signature := c.HashToG1(digest).Mul(sk)

	left := c.Pairing(c.GenG2.Copy(), signature)
	left = c.FExp(left)
	right := c.Pairing(pk, c.HashToG1(digest))
	right = c.FExp(right)

	assert.True(t, left.Equals(right))
}

func TestLocalSignVerify(t *testing.T) {
	sk := c.NewRandomZr(rand.Reader)

	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	sig := localSign(sk, digest)
	pk := c.GenG2.Copy().Mul(sk)
	assert.NoError(t, localVerify(pk, digest, sig))
}

var gsig2 *bn254.G1Affine
var gsig *math.G1
var gerr error

// go test -benchmem -bench BenchmarkLocalSignVerify -run=^$ -cpu=1
func BenchmarkLocalSignVerify(b *testing.B) {
	sk := c.NewRandomZr(rand.Reader)

	// hash our message
	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	// sign
	sig := localSign(sk, digest)
	pk := c.GenG2.Copy().Mul(sk)

	b.Run(fmt.Sprintf("sign"), func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var sig *math.G1
			for pb.Next() {
				sig = localSign(sk, digest)
			}
			// store results to prevent compiler optimizations
			gsig = sig
		})
		b.StopTimer()
	})

	b.Run(fmt.Sprintf("verify"), func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var err error
			for pb.Next() {
				err = localVerify(pk, digest, sig)
			}
			// store results to prevent compiler optimizations
			gerr = err
		})
		b.StopTimer()
	})

}

// go test -benchmem -bench BenchmarkLocalSignVerify2 -run=^$ -cpu=1
func BenchmarkLocalSignVerify2(b *testing.B) {
	// create random sk
	res := new(big.Int)
	v := &fr.Element{}
	_, err := v.SetRandom()
	if err != nil {
		panic(err)
	}
	sk := v.BigInt(res)

	// hash our message
	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	// sign
	sig := localSign2(sk, digest)

	// create pk
	_, _, _, g2 := bn254.Generators()
	pk := g2.ScalarMultiplication(&g2, sk)

	b.Run(fmt.Sprintf("sign"), func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var sig *bn254.G1Affine
			for pb.Next() {
				sig = localSign2(sk, digest)
			}
			// store results to prevent compiler optimizations
			gsig2 = sig
		})
		b.StopTimer()
	})

	b.Run(fmt.Sprintf("verify"), func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var err error
			for pb.Next() {
				err = localVerify2(pk, digest, sig)
			}
			// store results to prevent compiler optimizations
			gerr = err
		})
		b.StopTimer()
	})

}

func TestLocalThresholdBLS(t *testing.T) {
	shares := localGen(3, 2)
	pks := localCreatePublicKeys(shares)

	digest := sha256.Sum256([]byte("the little fox jumps over the lazy dog"))

	var signatures []*math.G1
	for i := 0; i < len(shares); i++ {
		signatures = append(signatures, localSign(shares[i], digest[:]))
	}

	for i := 0; i < len(shares); i++ {
		assert.NoError(t, localVerify(pks[i], digest[:], signatures[i]))
	}

	thresholdSignature := localAggregateSignatures(signatures[:2], 1, 2)
	thresholdPK := localAggregatePublicKeys(pks, 1, 2)

	assert.NoError(t, localVerify(thresholdPK, digest[:], thresholdSignature))
}
