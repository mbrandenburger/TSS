/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"crypto/rand"
	"fmt"
	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

func localGen(n, t int) Shares {
	_, shares := (&SSS{Threshold: t}).Gen(n, rand.Reader)
	return shares
}

func localCreatePublicKeys(shares Shares) []*math.G2 {
	publicKeys := make([]*math.G2, len(shares))
	for i := 0; i < len(shares); i++ {
		publicKeys[i] = c.GenG2.Copy().Mul(shares[i])
	}

	return publicKeys
}

func localAggregatePublicKeys(pks []*math.G2, evaluationPoints ...int64) *math.G2 {
	zero := c.GenG2.Copy()
	zero.Sub(c.GenG2)

	sum := zero

	for i := 0; i < len(evaluationPoints); i++ {
		sum.Add(pks[evaluationPoints[i]-1].Mul(lagrangeCoefficient(evaluationPoints[i], evaluationPoints...)))
	}

	return sum
}

func localAggregateSignatures(signatures []*math.G1, evaluationPoints ...int64) *math.G1 {
	zero := c.GenG1.Copy()
	zero.Sub(zero)

	sum := zero

	var signatureIndex int
	for _, evaluationPoint := range evaluationPoints {
		sum.Add(signatures[signatureIndex].Mul(lagrangeCoefficient(evaluationPoint, evaluationPoints...)))
		signatureIndex++
	}

	return sum
}

func localSign(sk *math.Zr, digest []byte) *math.G1 {
	return c.HashToG1(digest).Mul(sk)
}

func localVerify(pk *math.G2, digest []byte, sig *math.G1) error {
	left := c.Pairing(c.GenG2.Copy(), sig)
	left = c.FExp(left)
	right := c.Pairing(pk, c.HashToG1(digest))
	right = c.FExp(right)
	if left.Equals(right) {
		return nil
	}

	return fmt.Errorf("signature mismatch")
}

func localSign2(sk *big.Int, digest []byte) *bn254.G1Affine {
	g1, _ := bn254.HashToG1(digest, []byte{})
	return g1.ScalarMultiplication(&g1, sk)
}

func localVerify2(pk *bn254.G2Affine, digest []byte, sig *bn254.G1Affine) error {
	left, _ := bn254.Pair([]bn254.G1Affine{*sig}, []bn254.G2Affine{*pk})
	g1, _ := bn254.HashToG1(digest, []byte{})
	right, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{*pk})

	if left.Equal(&right) {
		return nil
	}

	return fmt.Errorf("signature mismatch")
}

func localAggregateSignatures2(signatures []*bn254.G1Affine, evaluationPoints ...int64) *bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	raw := g1.Bytes()

	zero, err := NewG1FromBytes(raw[:])
	if err != nil {
		panic(fmt.Sprintf("could not generate point %v", err))
	}

	zero.Sub(zero, zero)

	sum := zero

	var signatureIndex int
	for _, evaluationPoint := range evaluationPoints {

		i, _ := lagrangeCoefficient(evaluationPoint, evaluationPoints...).Int()

		zr := fr.NewElement(uint64(i))
		bi := &big.Int{}
		bi = zr.BigInt(bi)

		p := &bn254.G1Affine{}
		p.Set(signatures[signatureIndex])
		p = p.ScalarMultiplication(p, bi)

		sum = sum.Add(sum, p)

		signatureIndex++
	}

	return sum
}

func NewG2FromBytes(b []byte) (*bn254.G2Affine, error) {
	g2 := &bn254.G2Affine{}
	if _, err := g2.SetBytes(b); err != nil {
		return nil, fmt.Errorf("set bytes failed [%s]", err.Error())
	}
	return g2, nil
}

func NewG1FromBytes(b []byte) (*bn254.G1Affine, error) {
	g1 := &bn254.G1Affine{}
	if _, err := g1.SetBytes(b); err != nil {
		return nil, fmt.Errorf("set bytes failed [%s]", err.Error())
	}
	return g1, nil
}
