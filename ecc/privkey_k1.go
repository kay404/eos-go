package ecc

import (
	"fmt"

	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
	"github.com/eoscanada/eos-go/btcsuite/btcutil/base58"
)

type innerK1PrivateKey struct {
	privKey *btcec.PrivateKey
}

func (k *innerK1PrivateKey) publicKey() PublicKey {
	return PublicKey{Curve: CurveK1, Content: k.privKey.PubKey().SerializeCompressed(), inner: &innerK1PublicKey{}}
}

func (k *innerK1PrivateKey) sign(hash []byte) (out Signature, err error) {
	if len(hash) != 32 {
		return out, fmt.Errorf("hash should be 32 bytes")
	}
	compactSig, err := k.privKey.SignCanonical(btcec.S256(), hash)

	if err != nil {
		return out, fmt.Errorf("canonical, %s", err)
	}

	return Signature{Curve: CurveK1, Content: compactSig, inner: &innerK1Signature{}}, nil
}

func (k *innerK1PrivateKey) string() string {
	payload := k.privKey.D.Bytes()
	checksum := ripemd160checksum(payload, CurveK1.String())
	encodeLen := len(payload) + len(checksum)

	a := make([]byte, 0, encodeLen)
	a = append(a, payload...)
	a = append(a, checksum...)

	return "PVT" + "_" + CurveK1.String() + "_" + base58.Encode(a)
	// wif, _ := btcutil.NewWIF(k.privKey, '\x80', false) // no error possible
	// return wif.String()
}
