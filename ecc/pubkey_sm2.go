/*
 * @Description:
 * @Author: kay
 * @Date: 2020-07-29 23:08:00
 * @LastEditTime: 2020-07-29 23:45:58
 * @LastEditors: kay
 */

package ecc

import (
	"fmt"

	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
)

type innerSM2PublicKey struct {
}

func newInnerSM2PublicKey() innerPublicKey {
	return &innerSM2PublicKey{}
}

func (p *innerSM2PublicKey) key(content []byte) (*btcec.PublicKey, error) {
	key, err := btcec.ParsePubKeySM2(content, btcec.P256Sm2())
	if err != nil {
		return nil, fmt.Errorf("parsePubKey: %s", err)
	}

	return key, nil
}

func (p *innerSM2PublicKey) prefix() string {
	return PublicKeySM2Prefix
}

func (p *innerSM2PublicKey) keyMaterialSize() *int {
	return publicKeyDataSize
}
