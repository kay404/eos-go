package ecc

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
	"github.com/eoscanada/eos-go/btcsuite/btcutil"
	"github.com/eoscanada/eos-go/btcsuite/btcutil/base58"
)

func NewRandomPrivateKey() (*PrivateKey, error) {
	return newRandomPrivateKey(cryptorand.Reader)
}

func NewDeterministicPrivateKey(randSource io.Reader) (*PrivateKey, error) {
	return newRandomPrivateKey(randSource)
}

func newRandomPrivateKey(randSource io.Reader) (*PrivateKey, error) {
	rawPrivKey := make([]byte, 32)
	written, err := io.ReadFull(randSource, rawPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error feeding crypto-rand numbers to seed ephemeral private key: %s", err)
	}
	if written != 32 {
		return nil, fmt.Errorf("couldn't write 32 bytes of randomness to seed ephemeral private key")
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.P256Sm2(), rawPrivKey)

	inner := &innerSM2PrivateKey{privKey: privKey}
	return &PrivateKey{Curve: CurveSM2, inner: inner}, nil
}

func NewPrivateKey(wif string) (*PrivateKey, error) {
	// Strip potential prefix, and set curve
	// var privKeyMaterial string
	
	privateKeyPrefix, curvePrefix, payload, err := stringToKey(wif)
	if err != nil {
		return nil , err
	}
	if privateKeyPrefix == "PVT" { // "PVT_"

		// privKeyMaterial = wif[len(PrivateKeyPrefix):]
		// prefixPosition := strings.LastIndexAny(privKeyMaterial, "_")
		
		// curvePrefix := privKeyMaterial[:prefixPosition + 1]
		// privKeyMaterial = privKeyMaterial[prefixPosition + 1:] // remove "K1_"...

		switch curvePrefix {
		case "K1":

			privKey, _ := getKeyByPrivateRawData(CurveK1.String(), payload)
			// if err != nil {
			// 	return nil, err
			// }
			inner := &innerK1PrivateKey{privKey: privKey}
			return &PrivateKey{Curve: CurveK1, inner: inner}, nil
		case "R1":

			inner := &innerR1PrivateKey{}
			return &PrivateKey{Curve: CurveR1, inner: inner}, nil
		case "SM2":
			
			privKey, _ := getKeyByPrivateRawData(CurveSM2.String(), payload)
			if err != nil {
				return nil, err
			}
			inner := &innerSM2PrivateKey{privKey: privKey}
			return &PrivateKey{Curve: CurveSM2, inner: inner}, nil
		case "WA":

			inner := &innerWAPrivateKey{}
			return &PrivateKey{Curve: CurveWA, inner: inner}, nil

		default:
			return nil, fmt.Errorf("unsupported curve prefix %q", curvePrefix)
		}

	} else { // no-prefix, like before

		wifObj, err := btcutil.DecodeWIF(wif)
		if err != nil {
			return nil, err
		}
		inner := &innerK1PrivateKey{privKey: wifObj.PrivKey}
		return &PrivateKey{Curve: CurveK1, inner: inner}, nil
	}
}

func getKeyByPrivateRawData(curveType string, privateRawData []byte) (*btcec.PrivateKey, *btcec.PublicKey) {
	if curveType == "SM2" {
		return btcec.PrivKeyFromBytes(btcec.P256Sm2(), privateRawData)
	}
	return btcec.PrivKeyFromBytes(btcec.S256(), privateRawData)
}

func stringToKey(keyStr string) (string, string, []byte, error) {
	arr := strings.Split(keyStr, "_")
	if len(arr) != 3 || (arr[0] != "PUB" && arr[0] != "PVT" && arr[0] != "SIG") {
		return "", "", nil, fmt.Errorf("unrecognized key format")
	}

	curveType := arr[1]
	rawData := base58.Decode(arr[2])
	payloadLen := len(rawData) - 4
	payload := rawData[0:payloadLen]
	checksum := rawData[payloadLen:]
	reChecksum := ripemd160checksum(payload, curveType)
	if !bytes.Equal(checksum, reChecksum) {
		return "", "", nil, fmt.Errorf("checksum doesn't match")
	}

	return arr[0], curveType, payload, nil
}

func NewPrivateKeyFromSeed(seed string) (*PrivateKey, error) {
	hashByte := sha256.Sum256([]byte(seed))
	privateKey, err := NewDeterministicPrivateKey(bytes.NewBuffer(hashByte[:]))
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

type innerPrivateKey interface {
	publicKey() PublicKey
	sign(hash []byte) (out Signature, err error)
	string() string
}

type PrivateKey struct {
	Curve CurveID

	inner innerPrivateKey
}

func (p *PrivateKey) PublicKey() PublicKey {
	return p.inner.publicKey()
}

// Sign signs a 32 bytes SHA256 hash..
func (p *PrivateKey) Sign(hash []byte) (out Signature, err error) {
	return p.inner.sign(hash)
}

func (p *PrivateKey) String() string {
	return p.inner.string()
}

func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *PrivateKey) UnmarshalJSON(v []byte) (err error) {
	var s string
	if err = json.Unmarshal(v, &s); err != nil {
		return
	}

	newPrivKey, err := NewPrivateKey(s)
	if err != nil {
		return
	}

	*p = *newPrivKey

	return
}
