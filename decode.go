// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package header

import (
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/rlp"
)

// DetectFormat determines the header format from RLP-encoded data.
// Returns the format and number of fields detected.
func DetectFormat(data []byte) (Format, int, error) {
	fields, err := countRLPFields(data)
	if err != nil {
		return FormatUnknown, 0, err
	}

	switch fields {
	case 15:
		return Format15, fields, nil
	case 16:
		return Format16, fields, nil
	case 17:
		return Format17, fields, nil
	case 18:
		return Format18, fields, nil
	case 19:
		return Format19Lux, fields, nil
	case 20:
		return Format20, fields, nil
	default:
		if fields > 20 {
			return Format20, fields, nil // Extended format
		}
		return FormatUnknown, fields, fmt.Errorf("unknown header format with %d fields", fields)
	}
}

// Decode decodes RLP-encoded header data, automatically detecting the format.
func Decode(data []byte) (*types.Header, Format, error) {
	format, fields, err := DetectFormat(data)
	if err != nil {
		return nil, FormatUnknown, err
	}

	switch format {
	case Format15:
		return decode15(data)
	case Format16:
		return decode16(data)
	case Format17:
		return decode17(data)
	case Format18:
		return decode18(data)
	case Format19Lux:
		return decode19(data)
	case Format20:
		return decode20(data)
	default:
		return nil, FormatUnknown, fmt.Errorf("unsupported format with %d fields", fields)
	}
}

// DecodeGenesis decodes a genesis block header (16-field format).
func DecodeGenesis(data []byte) (*types.Header, error) {
	h, _, err := decode16(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode genesis header: %w", err)
	}
	return h, nil
}

// DecodePostGenesis decodes a post-genesis block header (19-field format).
func DecodePostGenesis(data []byte) (*types.Header, error) {
	h, _, err := decode19(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode post-genesis header: %w", err)
	}
	return h, nil
}

// countRLPFields counts the number of fields in an RLP-encoded list.
func countRLPFields(data []byte) (int, error) {
	content, _, err := rlp.SplitList(data)
	if err != nil {
		return 0, fmt.Errorf("invalid RLP list: %w", err)
	}

	count := 0
	for len(content) > 0 {
		_, rest, err := rlp.SplitString(content)
		if err != nil {
			return 0, fmt.Errorf("invalid RLP element: %w", err)
		}
		count++
		content = rest
	}
	return count, nil
}

// hdr15 is the 15-field pre-London header format.
type hdr15 struct {
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
}

// hdr18 is the 18-field header format with ExtDataGasUsed.
type hdr18 struct {
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
	ExtDataHash    *common.Hash `rlp:"nil"`
	ExtDataGasUsed *big.Int
}

// hdr19ptr is the 19-field header format with ExtDataHash as pointer.
type hdr19ptr struct {
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
	ExtDataHash    *common.Hash `rlp:"nil"`
	ExtDataGasUsed *big.Int
	BlockGasCost   *big.Int
}

// hdr20 is the 20-field header format (Lux extended).
type hdr20 struct {
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
	ExtDataHash    *common.Hash `rlp:"nil"`
	ExtDataGasUsed *big.Int
	BlockGasCost   *big.Int
	BlobGasUsed    *uint64
}

func decode15(data []byte) (*types.Header, Format, error) {
	var h hdr15
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
	}, Format15, nil
}

func decode16(data []byte) (*types.Header, Format, error) {
	var h hdr16
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
	}, Format16, nil
}

func decode17(data []byte) (*types.Header, Format, error) {
	var h hdr17
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
	}, Format17, nil
}

func decode18(data []byte) (*types.Header, Format, error) {
	var h hdr18
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
		ExtDataHash:    h.ExtDataHash,
		ExtDataGasUsed: h.ExtDataGasUsed,
	}, Format18, nil
}

func decode19(data []byte) (*types.Header, Format, error) {
	// Try Lux value-type format first (ExtDataHash as common.Hash, not pointer)
	var hlux hdr19val
	if err := rlp.DecodeBytes(data, &hlux); err == nil {
		extHash := hlux.ExtDataHash // Copy to get pointer
		return &types.Header{
			ParentHash:     hlux.ParentHash,
			UncleHash:      hlux.UncleHash,
			Coinbase:       hlux.Coinbase,
			Root:           hlux.Root,
			TxHash:         hlux.TxHash,
			ReceiptHash:    hlux.ReceiptHash,
			Bloom:          hlux.Bloom,
			Difficulty:     hlux.Difficulty,
			Number:         hlux.Number,
			GasLimit:       hlux.GasLimit,
			GasUsed:        hlux.GasUsed,
			Time:           hlux.Time,
			Extra:          hlux.Extra,
			MixDigest:      hlux.MixDigest,
			Nonce:          hlux.Nonce,
			BaseFee:        hlux.BaseFee,
			ExtDataHash:    &extHash,
			ExtDataGasUsed: hlux.ExtDataGasUsed,
			BlockGasCost:   hlux.BlockGasCost,
		}, Format19Lux, nil
	}

	// Fall back to pointer format
	var h hdr19ptr
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
		ExtDataHash:    h.ExtDataHash,
		ExtDataGasUsed: h.ExtDataGasUsed,
		BlockGasCost:   h.BlockGasCost,
	}, Format19Lux, nil
}

func decode20(data []byte) (*types.Header, Format, error) {
	var h hdr20
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, FormatUnknown, err
	}
	return &types.Header{
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
		ExtDataHash:    h.ExtDataHash,
		ExtDataGasUsed: h.ExtDataGasUsed,
		BlockGasCost:   h.BlockGasCost,
		BlobGasUsed:    h.BlobGasUsed,
	}, Format20, nil
}
