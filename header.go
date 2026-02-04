// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package header provides isolated header format handling for Lux blockchain.
//
// This package encapsulates all header RLP encoding/decoding and hash computation
// logic for Lux and SubnetEVM chains, supporting multiple header formats:
//
//   - Format16: Post-London (EIP-1559), pre-ExtDataHash - used by Lux mainnet genesis
//   - Format17: With ExtDataHash only
//   - Format18: With ExtDataHash + ExtDataGasUsed
//   - Format19: Full Lux format with ExtDataHash, ExtDataGasUsed, BlockGasCost
//   - Format20+: Extended formats with Ethereum 2.0 fields
//
// The key design decision is that genesis blocks use Format16 (16 fields) to maintain
// compatibility with the original chain genesis hash. Post-genesis blocks use Format19
// with all Lux-specific fields.
//
// CRITICAL: ExtDataHash Type Handling
//
// Original SubnetEVM/coreth used common.Hash (value type) for ExtDataHash, which always
// encodes as 32 bytes (zero hash when empty). This package uses *common.Hash (pointer)
// but provides Hash19Value() for computing hashes compatible with original coreth format.
package header

import (
	"io"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/rlp"
	"golang.org/x/crypto/sha3"
)

// Format represents the RLP encoding format for headers.
type Format int

const (
	// FormatUnknown indicates the format could not be determined.
	FormatUnknown Format = 0

	// Format15 is pre-London (legacy Ethereum, no BaseFee).
	Format15 Format = 15

	// Format16 is post-London (EIP-1559) - USED BY LUX MAINNET GENESIS.
	// Fields: ParentHash, UncleHash, Coinbase, Root, TxHash, ReceiptHash,
	// Bloom, Difficulty, Number, GasLimit, GasUsed, Time, Extra, MixDigest, Nonce, BaseFee
	Format16 Format = 16

	// Format17 adds ExtDataHash.
	Format17 Format = 17

	// Format18 adds ExtDataGasUsed.
	Format18 Format = 18

	// Format19Lux is full Lux format with ExtDataHash as VALUE type.
	// This matches original coreth encoding where ExtDataHash was common.Hash, not pointer.
	Format19Lux Format = 19

	// Format20 adds Ethereum 2.0 fields or extends Lux format.
	Format20 Format = 20
)

// hdr16 is the 16-field header format (post-London, pre-ExtDataHash).
// This is the format used by Lux mainnet genesis block.
type hdr16 struct {
	ParentHash  common.Hash
	UncleHash   common.Hash
	Coinbase    common.Address
	Root        common.Hash
	TxHash      common.Hash
	ReceiptHash common.Hash
	Bloom       types.Bloom
	Difficulty  *big.Int
	Number      *big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   common.Hash
	Nonce       types.BlockNonce
	BaseFee     *big.Int
}

// hdr17 is the 17-field header format (with ExtDataHash as pointer).
type hdr17 struct {
	ParentHash  common.Hash
	UncleHash   common.Hash
	Coinbase    common.Address
	Root        common.Hash
	TxHash      common.Hash
	ReceiptHash common.Hash
	Bloom       types.Bloom
	Difficulty  *big.Int
	Number      *big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   common.Hash
	Nonce       types.BlockNonce
	BaseFee     *big.Int
	ExtDataHash *common.Hash `rlp:"nil"`
}

// hdr19val is the 19-field header format with ExtDataHash as VALUE type.
// This matches original coreth/SubnetEVM encoding where ExtDataHash was common.Hash.
// The VALUE type always encodes as 32 bytes (zero hash when empty).
type hdr19val struct {
	ParentHash     common.Hash
	UncleHash      common.Hash
	Coinbase       common.Address
	Root           common.Hash
	TxHash         common.Hash
	ReceiptHash    common.Hash
	Bloom          types.Bloom
	Difficulty     *big.Int
	Number         *big.Int
	GasLimit       uint64
	GasUsed        uint64
	Time           uint64
	Extra          []byte
	MixDigest      common.Hash
	Nonce          types.BlockNonce
	BaseFee        *big.Int
	ExtDataHash    common.Hash // VALUE type, not pointer - matches original coreth
	ExtDataGasUsed *big.Int
	BlockGasCost   *big.Int
}

// Hash16 computes the hash using 16-field format (post-London, pre-ExtDataHash).
// This is used for Lux mainnet genesis compatibility.
func Hash16(h *types.Header) common.Hash {
	return rlpHash(&hdr16{
		ParentHash:  h.ParentHash,
		UncleHash:   h.UncleHash,
		Coinbase:    h.Coinbase,
		Root:        h.Root,
		TxHash:      h.TxHash,
		ReceiptHash: h.ReceiptHash,
		Bloom:       h.Bloom,
		Difficulty:  h.Difficulty,
		Number:      h.Number,
		GasLimit:    h.GasLimit,
		GasUsed:     h.GasUsed,
		Time:        h.Time,
		Extra:       h.Extra,
		MixDigest:   h.MixDigest,
		Nonce:       h.Nonce,
		BaseFee:     h.BaseFee,
	})
}

// Hash17 computes the hash using 17-field format (with ExtDataHash).
func Hash17(h *types.Header) common.Hash {
	return rlpHash(&hdr17{
		ParentHash:  h.ParentHash,
		UncleHash:   h.UncleHash,
		Coinbase:    h.Coinbase,
		Root:        h.Root,
		TxHash:      h.TxHash,
		ReceiptHash: h.ReceiptHash,
		Bloom:       h.Bloom,
		Difficulty:  h.Difficulty,
		Number:      h.Number,
		GasLimit:    h.GasLimit,
		GasUsed:     h.GasUsed,
		Time:        h.Time,
		Extra:       h.Extra,
		MixDigest:   h.MixDigest,
		Nonce:       h.Nonce,
		BaseFee:     h.BaseFee,
		ExtDataHash: h.ExtDataHash,
	})
}

// Hash19Value computes the hash using 19-field format with ExtDataHash as VALUE type.
// This matches original coreth/SubnetEVM encoding where ExtDataHash was common.Hash.
// When h.ExtDataHash is nil, encodes as zero hash (32 zero bytes).
func Hash19Value(h *types.Header) common.Hash {
	var extDataHash common.Hash
	if h.ExtDataHash != nil {
		extDataHash = *h.ExtDataHash
	}

	return rlpHash(&hdr19val{
		ParentHash:     h.ParentHash,
		UncleHash:      h.UncleHash,
		Coinbase:       h.Coinbase,
		Root:           h.Root,
		TxHash:         h.TxHash,
		ReceiptHash:    h.ReceiptHash,
		Bloom:          h.Bloom,
		Difficulty:     h.Difficulty,
		Number:         h.Number,
		GasLimit:       h.GasLimit,
		GasUsed:        h.GasUsed,
		Time:           h.Time,
		Extra:          h.Extra,
		MixDigest:      h.MixDigest,
		Nonce:          h.Nonce,
		BaseFee:        h.BaseFee,
		ExtDataHash:    extDataHash,
		ExtDataGasUsed: h.ExtDataGasUsed,
		BlockGasCost:   h.BlockGasCost,
	})
}

// GenesisHash computes the genesis block hash using 16-field format.
// This is the canonical hash computation for Lux mainnet genesis.
func GenesisHash(h *types.Header) common.Hash {
	return Hash16(h)
}

// PostGenesisHash computes the hash for post-genesis blocks using 19-field format.
// This uses the VALUE type for ExtDataHash to match original coreth encoding.
func PostGenesisHash(h *types.Header) common.Hash {
	return Hash19Value(h)
}

// Encode16 encodes a header using the 16-field format.
func Encode16(h *types.Header, w io.Writer) error {
	return rlp.Encode(w, &hdr16{
		ParentHash:  h.ParentHash,
		UncleHash:   h.UncleHash,
		Coinbase:    h.Coinbase,
		Root:        h.Root,
		TxHash:      h.TxHash,
		ReceiptHash: h.ReceiptHash,
		Bloom:       h.Bloom,
		Difficulty:  h.Difficulty,
		Number:      h.Number,
		GasLimit:    h.GasLimit,
		GasUsed:     h.GasUsed,
		Time:        h.Time,
		Extra:       h.Extra,
		MixDigest:   h.MixDigest,
		Nonce:       h.Nonce,
		BaseFee:     h.BaseFee,
	})
}

// Encode19Value encodes a header using the 19-field format with ExtDataHash as value.
func Encode19Value(h *types.Header, w io.Writer) error {
	var extDataHash common.Hash
	if h.ExtDataHash != nil {
		extDataHash = *h.ExtDataHash
	}

	return rlp.Encode(w, &hdr19val{
		ParentHash:     h.ParentHash,
		UncleHash:      h.UncleHash,
		Coinbase:       h.Coinbase,
		Root:           h.Root,
		TxHash:         h.TxHash,
		ReceiptHash:    h.ReceiptHash,
		Bloom:          h.Bloom,
		Difficulty:     h.Difficulty,
		Number:         h.Number,
		GasLimit:       h.GasLimit,
		GasUsed:        h.GasUsed,
		Time:           h.Time,
		Extra:          h.Extra,
		MixDigest:      h.MixDigest,
		Nonce:          h.Nonce,
		BaseFee:        h.BaseFee,
		ExtDataHash:    extDataHash,
		ExtDataGasUsed: h.ExtDataGasUsed,
		BlockGasCost:   h.BlockGasCost,
	})
}

// rlpHash computes the Keccak256 hash of the RLP encoding of x.
func rlpHash(x interface{}) common.Hash {
	var h common.Hash
	hasher := sha3.NewLegacyKeccak256()
	rlp.Encode(hasher, x)
	hasher.Sum(h[:0])
	return h
}
