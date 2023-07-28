package main

import (
	"bytes"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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

func main() {
	// TODO: cast block X -j > file.json
	// then run this with json file input
	// take the header out of the Block type
	// rlp comes out

	// create header with blob fields
	headerOne := &types.Header{
		ParentHash:      common.HexToHash("0x13a7ec98912f917b3e804654e37c9866092043c13eb8eab94eb64818e886cff5"),
		UncleHash:       common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:        common.HexToAddress("0xf97e180c050e5ab072211ad2c213eb5aee4df134"),
		Root:            common.HexToHash("0xec229dbe85b0d3643ad0f471e6ec1a36bbc87deffbbd970762d22a53b35d068a"),
		TxHash:          common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		ReceiptHash:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		Bloom:           types.Bloom{},
		Difficulty:      big.NewInt(0),
		Number:          big.NewInt(0x30598),
		GasLimit:        0x1c9c380,
		GasUsed:         0x0,
		Time:            0x64c40d54,
		Extra:           []byte("0xd883010c01846765746888676f312e32302e35856c696e7578"),
		MixDigest:       common.HexToHash("0x70ccadc40b16e2094954b1064749cc6fbac783c1712f1b271a8aac3eda2f2325"),
		Nonce:           types.BlockNonce{},
		BaseFee:         big.NewInt(0x7),
		WithdrawalsHash: new(common.Hash),
		BlobGasUsed:     new(uint64),
		ExcessBlobGas:   new(uint64),
	}

	// set pointer fields
	*headerOne.WithdrawalsHash = common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	*headerOne.BlobGasUsed = 0x0
	*headerOne.ExcessBlobGas = 0x1600000

	// create writer
	buf := new(bytes.Buffer)

	// encode header
	if err := headerOne.EncodeRLP(buf); err != nil {
		log.Fatal(err)
	}

	// write as hex
	fmt.Printf("%x\n", buf.Bytes())
}
