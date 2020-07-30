/*
 * @Description:
 * @Author: kay
 * @Date: 2020-07-29 23:12:07
 * @LastEditTime: 2020-07-29 23:24:46
 * @LastEditors: kay
 */

package ecc

import (
	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
	"github.com/eoscanada/eos-go/btcsuite/btcutil/base58"
)

type innerSM2Signature struct {
}

func newInnerSM2Signature() innerSignature {
	return &innerSM2Signature{}
}

// verify checks the signature against the pubKey. `hash` is a sha256
// hash of the payload to verify.
func (s *innerSM2Signature) verify(content []byte, hash []byte, pubKey PublicKey) bool {
	recoveredKey, _, err := btcec.RecoverCompactSM2(btcec.P256Sm2(), content, hash)
	if err != nil {
		return false
	}
	key, err := pubKey.Key()
	if err != nil {
		return false
	}
	if recoveredKey.IsEqual(key) {
		return true
	}
	return false
}

func (s *innerSM2Signature) publicKey(content []byte, hash []byte) (out PublicKey, err error) {

	recoveredKey, _, err := btcec.RecoverCompactSM2(btcec.P256Sm2(), content, hash)

	if err != nil {
		return out, err
	}

	return PublicKey{
		Curve:   CurveSM2,
		Content: recoveredKey.SerializeCompressed(),
		inner:   &innerSM2PublicKey{},
	}, nil
}

func (s innerSM2Signature) string(content []byte) string {
	checksum := Ripemd160checksumHashCurve(content, CurveSM2.String())
	buf := append(content[:], checksum...)
	return SignatureSM2Prefix + base58.Encode(buf)
}

func (s innerSM2Signature) signatureMaterialSize() *int {
	return signatureDataSize
}
