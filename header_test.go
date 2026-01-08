// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package header

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// Lux Mainnet Genesis constants
const (
	LuxMainnetGenesisHash  = "0x3f4fa2a0b0ce089f52bf0ae9199c75ffdd76ecafc987794050cb0d286f1ec61e"
	LuxMainnetStateRoot    = "0x2d1cedac263020c5c56ef962f6abe0da1f5217bdc6468f8c9258a0ea23699e80"
	LuxMainnetTimestamp    = 1730446786
	LuxMainnetGasLimit     = 12000000
	LuxMainnetBaseFee      = 25000000000
)

// Zoo Mainnet Genesis constants
const (
	ZooMainnetGenesisHash = "0x7c548af47de27560779ccc67dda32a540944accc71dac3343da3b9cd18f14933"
	ZooMainnetStateRoot   = "0x2d1cedac263020c5c56ef962f6abe0da1f5217bdc6468f8c9258a0ea23699e80"
	ZooMainnetTimestamp   = 1730668995
	ZooMainnetGasLimit    = 12000000
	ZooMainnetBaseFee     = 25000000000
)

// TestLuxMainnetGenesisHash verifies the genesis hash computation for Lux mainnet.
// The genesis uses 16-field format (post-London, pre-ExtDataHash).
func TestLuxMainnetGenesisHash(t *testing.T) {
	// Create the Lux mainnet genesis header
	header := &types.Header{
		ParentHash:  common.Hash{},
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        common.HexToHash(LuxMainnetStateRoot),
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    LuxMainnetGasLimit,
		GasUsed:     0,
		Time:        LuxMainnetTimestamp,
		Extra:       []byte{},
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
		BaseFee:     big.NewInt(LuxMainnetBaseFee),
	}

	// Compute hash using 16-field format
	hash := Hash16(header)

	expectedHash := common.HexToHash(LuxMainnetGenesisHash)
	if hash != expectedHash {
		t.Errorf("Lux mainnet genesis hash mismatch:\n  have: %s\n  want: %s",
			hash.Hex(), expectedHash.Hex())
	}

	// Also verify via GenesisHash convenience function
	genesisHash := GenesisHash(header)
	if genesisHash != expectedHash {
		t.Errorf("GenesisHash() mismatch:\n  have: %s\n  want: %s",
			genesisHash.Hex(), expectedHash.Hex())
	}
}

// TestZooMainnetGenesisHash verifies the genesis hash computation for Zoo mainnet.
func TestZooMainnetGenesisHash(t *testing.T) {
	// Create the Zoo mainnet genesis header
	header := &types.Header{
		ParentHash:  common.Hash{},
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        common.HexToHash(ZooMainnetStateRoot),
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    ZooMainnetGasLimit,
		GasUsed:     0,
		Time:        ZooMainnetTimestamp,
		Extra:       []byte{},
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
		BaseFee:     big.NewInt(ZooMainnetBaseFee),
	}

	// Compute hash using 16-field format
	hash := Hash16(header)

	expectedHash := common.HexToHash(ZooMainnetGenesisHash)
	if hash != expectedHash {
		t.Errorf("Zoo mainnet genesis hash mismatch:\n  have: %s\n  want: %s",
			hash.Hex(), expectedHash.Hex())
	}
}

// TestFormat16Encoding tests the 16-field header encoding.
func TestFormat16Encoding(t *testing.T) {
	header := &types.Header{
		ParentHash:  common.Hash{},
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        common.HexToHash(LuxMainnetStateRoot),
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    LuxMainnetGasLimit,
		GasUsed:     0,
		Time:        LuxMainnetTimestamp,
		Extra:       []byte{},
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
		BaseFee:     big.NewInt(LuxMainnetBaseFee),
	}

	// Encode using 16-field format
	var buf bytes.Buffer
	if err := Encode16(header, &buf); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Verify field count
	format, fields, err := DetectFormat(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to detect format: %v", err)
	}
	if format != Format16 {
		t.Errorf("expected Format16, got %v", format)
	}
	if fields != 16 {
		t.Errorf("expected 16 fields, got %d", fields)
	}

	// Decode and verify
	decoded, detectedFormat, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if detectedFormat != Format16 {
		t.Errorf("expected Format16, got %v", detectedFormat)
	}
	if decoded.Root != header.Root {
		t.Errorf("state root mismatch")
	}
	if decoded.BaseFee.Cmp(header.BaseFee) != 0 {
		t.Errorf("base fee mismatch")
	}
}

// TestFormat19ValueEncoding tests the 19-field header encoding with value-type ExtDataHash.
func TestFormat19ValueEncoding(t *testing.T) {
	extDataHash := common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	header := &types.Header{
		ParentHash:     common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		UncleHash:      types.EmptyUncleHash,
		Coinbase:       common.Address{},
		Root:           common.HexToHash(LuxMainnetStateRoot),
		TxHash:         types.EmptyTxsHash,
		ReceiptHash:    types.EmptyReceiptsHash,
		Bloom:          types.Bloom{},
		Difficulty:     big.NewInt(0),
		Number:         big.NewInt(1),
		GasLimit:       LuxMainnetGasLimit,
		GasUsed:        21000,
		Time:           LuxMainnetTimestamp + 2,
		Extra:          []byte{},
		MixDigest:      common.Hash{},
		Nonce:          types.BlockNonce{},
		BaseFee:        big.NewInt(LuxMainnetBaseFee),
		ExtDataHash:    &extDataHash,
		ExtDataGasUsed: big.NewInt(0),
		BlockGasCost:   big.NewInt(100000),
	}

	// Encode using 19-field value format
	var buf bytes.Buffer
	if err := Encode19Value(header, &buf); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Verify field count
	format, fields, err := DetectFormat(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to detect format: %v", err)
	}
	if format != Format19Lux {
		t.Errorf("expected Format19Lux, got %v", format)
	}
	if fields != 19 {
		t.Errorf("expected 19 fields, got %d", fields)
	}

	// Decode and verify
	decoded, detectedFormat, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if detectedFormat != Format19Lux {
		t.Errorf("expected Format19Lux, got %v", detectedFormat)
	}
	if decoded.Root != header.Root {
		t.Errorf("state root mismatch")
	}
	if decoded.ExtDataHash == nil || *decoded.ExtDataHash != extDataHash {
		t.Errorf("ExtDataHash mismatch")
	}
	if decoded.BlockGasCost == nil || decoded.BlockGasCost.Cmp(header.BlockGasCost) != 0 {
		t.Errorf("BlockGasCost mismatch")
	}

	// Verify hash computation
	hash := Hash19Value(header)
	decodedHash := Hash19Value(decoded)
	if hash != decodedHash {
		t.Errorf("hash mismatch after round-trip:\n  original: %s\n  decoded: %s",
			hash.Hex(), decodedHash.Hex())
	}
}

// TestHash16VsHash19 verifies that Hash16 and Hash19Value produce different results
// for the same header (when ExtDataHash is nil, Hash19Value encodes zero hash).
func TestHash16VsHash19(t *testing.T) {
	header := &types.Header{
		ParentHash:     common.Hash{},
		UncleHash:      types.EmptyUncleHash,
		Coinbase:       common.Address{},
		Root:           common.HexToHash(LuxMainnetStateRoot),
		TxHash:         types.EmptyTxsHash,
		ReceiptHash:    types.EmptyReceiptsHash,
		Bloom:          types.Bloom{},
		Difficulty:     big.NewInt(0),
		Number:         big.NewInt(0),
		GasLimit:       LuxMainnetGasLimit,
		GasUsed:        0,
		Time:           LuxMainnetTimestamp,
		Extra:          []byte{},
		MixDigest:      common.Hash{},
		Nonce:          types.BlockNonce{},
		BaseFee:        big.NewInt(LuxMainnetBaseFee),
		ExtDataHash:    nil, // nil for genesis
		ExtDataGasUsed: big.NewInt(0),
		BlockGasCost:   big.NewInt(0),
	}

	hash16 := Hash16(header)
	hash19 := Hash19Value(header)

	// These should be different because:
	// - Hash16: 16 fields, no ExtDataHash
	// - Hash19Value: 19 fields, ExtDataHash as zero hash (32 bytes)
	if hash16 == hash19 {
		t.Errorf("Hash16 and Hash19Value should produce different hashes!\n  Hash16:     %s\n  Hash19Value: %s",
			hash16.Hex(), hash19.Hex())
	}

	t.Logf("Hash16 (genesis format):     %s", hash16.Hex())
	t.Logf("Hash19Value (post-genesis): %s", hash19.Hex())
}

// TestRoundTripAllFormats tests encoding and decoding for all formats.
func TestRoundTripAllFormats(t *testing.T) {
	tests := []struct {
		name   string
		format Format
		header *types.Header
	}{
		{
			name:   "Format16 (genesis)",
			format: Format16,
			header: &types.Header{
				ParentHash:  common.Hash{},
				UncleHash:   types.EmptyUncleHash,
				Coinbase:    common.Address{},
				Root:        common.HexToHash("0xdeadbeef"),
				TxHash:      types.EmptyTxsHash,
				ReceiptHash: types.EmptyReceiptsHash,
				Bloom:       types.Bloom{},
				Difficulty:  big.NewInt(0),
				Number:      big.NewInt(0),
				GasLimit:    12000000,
				GasUsed:     0,
				Time:        1730446786,
				Extra:       []byte{},
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
				BaseFee:     big.NewInt(25000000000),
			},
		},
		{
			name:   "Format19 (post-genesis)",
			format: Format19Lux,
			header: func() *types.Header {
				extHash := common.HexToHash("0xcafebabe")
				return &types.Header{
					ParentHash:     common.HexToHash("0x1234"),
					UncleHash:      types.EmptyUncleHash,
					Coinbase:       common.Address{},
					Root:           common.HexToHash("0xdeadbeef"),
					TxHash:         types.EmptyTxsHash,
					ReceiptHash:    types.EmptyReceiptsHash,
					Bloom:          types.Bloom{},
					Difficulty:     big.NewInt(0),
					Number:         big.NewInt(1),
					GasLimit:       12000000,
					GasUsed:        21000,
					Time:           1730446788,
					Extra:          []byte{},
					MixDigest:      common.Hash{},
					Nonce:          types.BlockNonce{},
					BaseFee:        big.NewInt(25000000000),
					ExtDataHash:    &extHash,
					ExtDataGasUsed: big.NewInt(0),
					BlockGasCost:   big.NewInt(100000),
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			var err error

			switch tt.format {
			case Format16:
				err = Encode16(tt.header, &buf)
			case Format19Lux:
				err = Encode19Value(tt.header, &buf)
			default:
				t.Fatalf("unsupported format: %v", tt.format)
			}
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			decoded, detectedFormat, err := Decode(buf.Bytes())
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			if detectedFormat != tt.format {
				t.Errorf("format mismatch: have %v, want %v", detectedFormat, tt.format)
			}

			if decoded.Number.Cmp(tt.header.Number) != 0 {
				t.Errorf("Number mismatch")
			}
			if decoded.Root != tt.header.Root {
				t.Errorf("Root mismatch")
			}
			if decoded.Time != tt.header.Time {
				t.Errorf("Time mismatch")
			}
		})
	}
}

// TestDecodeRealRLP tests decoding actual RLP from mainnet.
// This uses the exact RLP bytes from Lux mainnet genesis.
func TestDecodeRealRLP(t *testing.T) {
	// RLP bytes from Lux mainnet genesis (509 bytes, 16-field format)
	genesisRLP := common.FromHex("0xf901faa00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a02d1cedac263020c5c56ef962f6abe0da1f5217bdc6468f8c9258a0ea23699e80a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000808083b71b008084672485c280a000000000000000000000000000000000000000000000000000000000000000008800000000000000008505d21dba00")

	// Detect format
	format, fields, err := DetectFormat(genesisRLP)
	if err != nil {
		t.Fatalf("failed to detect format: %v", err)
	}
	if format != Format16 {
		t.Errorf("expected Format16, got %v (fields=%d)", format, fields)
	}

	// Decode
	decoded, detectedFormat, err := Decode(genesisRLP)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if detectedFormat != Format16 {
		t.Errorf("expected Format16, got %v", detectedFormat)
	}

	// Verify fields
	if decoded.Number.Uint64() != 0 {
		t.Errorf("Number should be 0, got %d", decoded.Number.Uint64())
	}
	if decoded.Root != common.HexToHash(LuxMainnetStateRoot) {
		t.Errorf("StateRoot mismatch: have %s, want %s",
			decoded.Root.Hex(), LuxMainnetStateRoot)
	}
	if decoded.Time != LuxMainnetTimestamp {
		t.Errorf("Timestamp mismatch: have %d, want %d",
			decoded.Time, LuxMainnetTimestamp)
	}
	if decoded.GasLimit != LuxMainnetGasLimit {
		t.Errorf("GasLimit mismatch: have %d, want %d",
			decoded.GasLimit, LuxMainnetGasLimit)
	}
	if decoded.BaseFee.Int64() != LuxMainnetBaseFee {
		t.Errorf("BaseFee mismatch: have %d, want %d",
			decoded.BaseFee.Int64(), LuxMainnetBaseFee)
	}

	// Verify hash
	hash := Hash16(decoded)
	expectedHash := common.HexToHash(LuxMainnetGenesisHash)
	if hash != expectedHash {
		t.Errorf("hash mismatch:\n  have: %s\n  want: %s",
			hash.Hex(), expectedHash.Hex())
	}

	// Also verify via rlpHash directly on RLP
	rlpDecoded := rlpHash(decoded)
	// Note: This won't match because rlpHash uses default encoding
	// which is different from Format16. The Hash16 function is correct.
	t.Logf("Direct RLP hash: %s (may differ due to encoding)", rlpDecoded.Hex())
	t.Logf("Hash16 hash:     %s (correct genesis hash)", hash.Hex())
}

// BenchmarkHash16 benchmarks the 16-field hash computation.
func BenchmarkHash16(b *testing.B) {
	header := &types.Header{
		ParentHash:  common.Hash{},
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        common.HexToHash(LuxMainnetStateRoot),
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    LuxMainnetGasLimit,
		GasUsed:     0,
		Time:        LuxMainnetTimestamp,
		Extra:       []byte{},
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
		BaseFee:     big.NewInt(LuxMainnetBaseFee),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash16(header)
	}
}

// BenchmarkHash19Value benchmarks the 19-field hash computation.
func BenchmarkHash19Value(b *testing.B) {
	extHash := common.HexToHash("0xcafebabe")
	header := &types.Header{
		ParentHash:     common.HexToHash("0x1234"),
		UncleHash:      types.EmptyUncleHash,
		Coinbase:       common.Address{},
		Root:           common.HexToHash(LuxMainnetStateRoot),
		TxHash:         types.EmptyTxsHash,
		ReceiptHash:    types.EmptyReceiptsHash,
		Bloom:          types.Bloom{},
		Difficulty:     big.NewInt(0),
		Number:         big.NewInt(1),
		GasLimit:       LuxMainnetGasLimit,
		GasUsed:        21000,
		Time:           LuxMainnetTimestamp + 2,
		Extra:          []byte{},
		MixDigest:      common.Hash{},
		Nonce:          types.BlockNonce{},
		BaseFee:        big.NewInt(LuxMainnetBaseFee),
		ExtDataHash:    &extHash,
		ExtDataGasUsed: big.NewInt(0),
		BlockGasCost:   big.NewInt(100000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash19Value(header)
	}
}
