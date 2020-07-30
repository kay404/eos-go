package eos_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	eos "github.com/eoscanada/eos-go"
	"github.com/eoscanada/eos-go/token"
)

func TestExampleAPI_PushTransaction_transfer_EOS(t *testing.T) {
	api := eos.New("http://121.89.208.188:8888")

	keyBag := &eos.KeyBag{}
	// err := keyBag.ImportPrivateKey(context.Background(), "PVT_SM2_oryHA92F1WTCQNCFK2ArgqoqzwW9iHoBKmZWzD7A11xtwfyeQ")
	err := keyBag.ImportPrivateKey(context.Background(), "PVT_K1_27UgcSqAMCgEV61ZzeAfBhvwkhkRSxTKDaQnrKqvqij5qD22FD")
	// fmt.Printf("privat Key: %v \n", keyBag.Keys[0].Curve.StringPrefix())
	if err != nil {
		panic(fmt.Errorf("import private key: %s", err))
	}
	api.SetSigner(keyBag)

	from := eos.AccountName("icbs")
	to := eos.AccountName("icbs.test")
	quantity, err := eos.NewEOSAssetFromString("1.0000 YLZ")
	memo := ""

	if err != nil {
		panic(fmt.Errorf("invalid quantity: %s", err))
	}

	txOpts := &eos.TxOptions{}
	if err := txOpts.FillFromChain(context.Background(), api); err != nil {
		panic(fmt.Errorf("filling tx opts: %s", err))
	}

	tx := eos.NewTransaction([]*eos.Action{token.NewTransfer(from, to, quantity, memo)}, txOpts)
	signedTx, packedTx, err := api.SignTransaction(context.Background(), tx, txOpts.ChainID, eos.CompressionNone)
	if err != nil {
		panic(fmt.Errorf("sign transaction: %s", err))
	}

	content, err := json.MarshalIndent(signedTx, "", "  ")
	if err != nil {
		panic(fmt.Errorf("json marshalling transaction: %s", err))
	}

	fmt.Println(string(content))
	fmt.Println()

	response, err := api.PushTransaction(context.Background(), packedTx)
	if err != nil {
		panic(fmt.Errorf("push transaction: %s", err))
	}

	fmt.Printf("Transaction [%s] submitted to the network succesfully.\n", hex.EncodeToString(response.Processed.ID))
	panic(fmt.Errorf("test"))
}

func readPrivateKey() string {
	// Right now, the key is read from an environment variable, it's an example after all.
	// In a real-world scenario, would you probably integrate with a real wallet or something similar
	envName := "PVT_K1_27UgcSqAMCgEV61ZzeAfBhvwkhkRSxTKDaQnrKqvqij5qD22FD"
	privateKey := os.Getenv(envName)
	fmt.Printf("privateKey %v\n", privateKey)
	if privateKey == "" {
		panic(fmt.Errorf("private key environment variable %q must be set", envName))
	}

	return privateKey
}
