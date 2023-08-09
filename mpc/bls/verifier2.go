/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"encoding/asn1"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Verifier2 struct {
	pks                []*bn254.G2Affine
	tPK                *bn254.G2Affine
	parties2EvalPoints map[uint16]int64
}

func (v *Verifier2) Init(rawPP []byte) error {
	pp := &PublicParams{}
	if _, err := asn1.Unmarshal(rawPP, pp); err != nil {
		return err
	}

	var err error
	v.pks = nil

	v.tPK, err = NewG2FromBytes(pp.ThresholdPK)
	if err != nil {
		return err
	}

	for _, rawPK := range pp.PublicKeys {
		pk, err := NewG2FromBytes(rawPK)
		if err != nil {
			return err
		}

		v.pks = append(v.pks, pk)
	}

	v.parties2EvalPoints = make(map[uint16]int64)
	for i, p := range pp.Parties {
		v.parties2EvalPoints[uint16(p)] = int64(i + 1)
	}

	return nil
}

func (v *Verifier2) AggregateSignatures(signatures [][]byte, signers []uint16) ([]byte, error) {
	if len(signers) == 0 {
		panic("no signers")
	}

	if len(signatures) != len(signers) {
		panic(fmt.Sprintf("%d signers but %d signatures", len(signers), len(signatures)))
	}

	sigs := make([]*bn254.G1Affine, len(signatures))
	for i := 0; i < len(signatures); i++ {
		sig, err := NewG1FromBytes(signatures[i])
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}

	evalPoints := make([]int64, len(signers))
	for i, signer := range signers {
		evalPoint, exists := v.parties2EvalPoints[signer]
		if !exists {
			panic(fmt.Sprintf("signature %d was signed by an unknown party %d", i, signer))
		}
		evalPoints[i] = evalPoint
	}

	a := localAggregateSignatures2(sigs, evalPoints...).Bytes()
	return a[:], nil
}

func (v *Verifier2) Verify(digest []byte, signature []byte) error {
	sig, err := NewG1FromBytes(signature)
	if err != nil {
		return err
	}

	return localVerify2(v.tPK, digest, sig)
}
