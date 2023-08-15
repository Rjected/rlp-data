package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// {
//     "hash": "0x539c9ea0a3ca49808799d3964b8b6607037227de26bc51073c6926963127087b",
//     "parentHash": "0x13a7ec98912f917b3e804654e37c9866092043c13eb8eab94eb64818e886cff5",
//     "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
//     "miner": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
//     "stateRoot": "0xec229dbe85b0d3643ad0f471e6ec1a36bbc87deffbbd970762d22a53b35d068a",
//     "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//     "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//     "number": "0x30598",
//     "gasUsed": "0x0",
//     "gasLimit": "0x1c9c380",
//     "extraData": "0xd883010c01846765746888676f312e32302e35856c696e7578",
//     "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//     "timestamp": "0x64c40d54",
//     "difficulty": "0x0",
//     "totalDifficulty": "0x1",
//     "sealFields": [],
//     "uncles": [],
//     "transactions": [],
//     "size": "0x242",
//     "mixHash": "0x70ccadc40b16e2094954b1064749cc6fbac783c1712f1b271a8aac3eda2f2325",
//     "nonce": "0x0000000000000000",
//     "baseFeePerGas": "0x7",
//     "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//     "withdrawals": [],
//     "author": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
//     "dataGasUsed": "0x0",
//     "excessDataGas": "0x1600000"
// },

var (
	key, _ = crypto.GenerateKey()
	withBlobs = createEmptyBlobTx(key, true)
	withBlobsStripped = withBlobs.WithoutBlobTxSidecar()
	withoutBlobs = createEmptyBlobTx(key, false)

    // test addr
    testAddr = common.HexToAddress("b94f5374fce5edbc8e2a8697c15331677e6ebf0b")

    // sign a tx
    emptyEip2718Tx = types.NewTx(&types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    3,
		To:       &testAddr,
		Value:    big.NewInt(10),
		Gas:      25000,
		GasPrice: big.NewInt(1),
		Data:     common.FromHex("5544"),
	})

    emptyTx = types.NewTransaction(
		0,
		common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
		big.NewInt(0), 0, big.NewInt(0),
		nil,
	)

    rightvrsTx, _ = types.NewTransaction(
		3,
		testAddr,
		big.NewInt(10),
		2000,
		big.NewInt(1),
		common.FromHex("5544"),
	).WithSignature(
		types.HomesteadSigner{},
		common.Hex2Bytes("98ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4a8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a301"),
	)

    signedEip2718Tx, _ = emptyEip2718Tx.WithSignature(
		types.NewEIP2930Signer(big.NewInt(1)),
		common.Hex2Bytes("c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b266032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d3752101"),
	)
)

func main() {

    // === pooled txs ===

    // create PooledTransactionsPacket
    pooledTxs := eth.PooledTransactionsPacket{signedEip2718Tx, withBlobs, rightvrsTx}

    // rlp rawvalue
    rawRlpSlice := make([]rlp.RawValue, len(pooledTxs))

    for _, tx := range pooledTxs {
        // create writer
        if encoded, err := rlp.EncodeToBytes(tx); err != nil {
            log.Fatal("Failed to encode transaction", "err", err)
        } else {
            rawRlpSlice = append(rawRlpSlice, encoded)
        }
    }

	// create writer
    if encodedTxs, err := rlp.EncodeToBytes(rawRlpSlice); err != nil {
        log.Fatal("Failed to encode pooled transactions packet", "err", err)
    } else {
        // write as hex
        fmt.Printf("%x\n", encodedTxs)
    }

    // === individual txs ===

	// create writer
    buf := new(bytes.Buffer)

	// encode with blob tx
	if err := withBlobs.EncodeRLP(buf); err != nil {
		log.Fatal(err)
	}

	// print tx
	// fmt.Printf("encoding transaction: %+v\n", withBlobs)

	// write as hex
	// fmt.Printf("%x\n", buf.Bytes())

    // create another writer for without blobs
    buf = new(bytes.Buffer)

    // encode without blob tx
	if err := withoutBlobs.EncodeRLP(buf); err != nil {
		log.Fatal(err)
	}

    // print tx
    // fmt.Printf("encoding transaction without blobs: %+v\n", withoutBlobs)

    // write as hex
    // fmt.Printf("%x\n", buf.Bytes())

    // create another writer with blobs stripped
    buf = new(bytes.Buffer)

    // encode with blob stripped tx
    if err := withBlobsStripped.EncodeRLP(buf); err != nil {
        log.Fatal(err)
    }

    // print tx
    // fmt.Printf("encoding transaction with blobs stripped: %+v\n", withBlobsStripped)

    // write as hex
    // fmt.Printf("%x\n", buf.Bytes())
}

var (
	emptyBlob          = kzg4844.Blob{}
	emptyBlobCommit, _ = kzg4844.BlobToCommitment(emptyBlob)
	emptyBlobProof, _  = kzg4844.ComputeBlobProof(emptyBlob, emptyBlobCommit)
)

func createEmptyBlobTx(key *ecdsa.PrivateKey, withSidecar bool) *types.Transaction {
	sidecar := &types.BlobTxSidecar{
		Blobs:       []kzg4844.Blob{emptyBlob},
		Commitments: []kzg4844.Commitment{emptyBlobCommit},
		Proofs:      []kzg4844.Proof{emptyBlobProof},
	}
	blobtx := &types.BlobTx{
		ChainID:    uint256.NewInt(1),
		Nonce:      5,
		GasTipCap:  uint256.NewInt(22),
		GasFeeCap:  uint256.NewInt(5),
		Gas:        25000,
		To:         common.Address{0x03, 0x04, 0x05},
		Value:      uint256.NewInt(99),
		Data:       make([]byte, 50),
		BlobFeeCap: uint256.NewInt(15),
		BlobHashes: sidecar.BlobHashes(),
	}
	if withSidecar {
		blobtx.Sidecar = sidecar
	}
	signer := types.NewCancunSigner(blobtx.ChainID.ToBig())
	return types.MustSignNewTx(key, signer, blobtx)
}
