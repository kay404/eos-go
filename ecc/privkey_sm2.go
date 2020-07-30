/*
 * @Description:
 * @Author: kay
 * @Date: 2020-07-29 23:01:34
 * @LastEditTime: 2020-07-30 09:01:25
 * @LastEditors: kay
 */
package ecc

import (
	"fmt"

	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
	"github.com/eoscanada/eos-go/btcsuite/btcutil/base58"
)

type innerSM2PrivateKey struct {
	privKey *btcec.PrivateKey
}

func (k *innerSM2PrivateKey) publicKey() PublicKey {
	return PublicKey{Curve: CurveSM2, Content: k.privKey.PubKey().SerializeCompressed(), inner: &innerSM2PublicKey{}}
}

func (k *innerSM2PrivateKey) sign(hash []byte) (out Signature, err error) {
	if len(hash) != 32 {
		return out, fmt.Errorf("hash should be 32 bytes")
	}
	// fmt
	compactSig, err := k.privKey.SignCanonicalInfiniteSM2(hash)

	if err != nil {
		return out, fmt.Errorf("canonical, %s", err)
	}

	return Signature{Curve: CurveSM2, Content: compactSig, inner: &innerSM2Signature{}}, nil
}

func (k *innerSM2PrivateKey) string() string {
	payload := k.privKey.D.Bytes()
	checksum := ripemd160checksum(payload, CurveSM2.String())
	encodeLen := len(payload) + len(checksum)

	a := make([]byte, 0, encodeLen)
	a = append(a, payload...)
	a = append(a, checksum...)

	return "PVT" + "_" + CurveSM2.String() + "_" + base58.Encode(a)
	// wif, _ := btcutil.NewWIF(k.privKey, '\x80', false) // no error possible
	// return wif.String()
}
