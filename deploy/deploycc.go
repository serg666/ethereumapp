package main

import (
	"os"
	"fmt"
	"log"
	"flag"
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/serg666/ethereumapp/nft"
)

func main() {
	dataDir := flag.String("data-dir", "~datadir", "Data dir")
	baseAccount := flag.String("base-account", "0x5883b8991821d1d80f9b64d44d2fc75cb8e2c16a", "Network base account")
	name := flag.String("token-name", "SampleNFT", "Token name")
	symbol := flag.String("token-symbol", "NFT", "Token symbol")
	flag.Parse()

	ipc := fmt.Sprintf("%s/geth.ipc", *dataDir)
	ethClient, err := ethclient.Dial(ipc)
	if err != nil {
		log.Fatalf("Can not connect to ethereum network: %v", err)
	}
	defer ethClient.Close()

	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		log.Fatalf("Failed to get chain id: %v", err)
	}

	account := accounts.Account{
		Address: common.HexToAddress(*baseAccount),
	}

        ks := keystore.NewKeyStore(fmt.Sprintf("%s/keystore", *dataDir), keystore.StandardScryptN, keystore.StandardScryptP)
        ks.Unlock(account, os.Getenv("BASE_ACC_PASSWD"))

	auth, err := bind.NewKeyStoreTransactorWithChainID(ks, account, chainID)
	if err != nil {
		log.Fatalf("Failed to create authorized transactor: %v", err)
	}

	// Deploy a new awesome contract for the binding demo
	address, tx, token, err := nft.DeploySampleNFT(auth, ethClient, *name, *symbol)
	if err != nil {
		log.Fatalf("Failed to deploy new token contract: %v", err)
	}

	log.Printf("Token: %v", token)
	log.Printf("Contract address: %s", address)
	log.Printf("Transaction hash: 0x%x", tx.Hash())
}
