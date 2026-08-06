// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	aa "golang.org/x/arch/arm64/arm64asm"
)

func TestExtractTLSOffset(t *testing.T) {
	testdata := []struct {
		name          string
		code          []byte
		baseAddr      uint64
		expected      int32
		expectedError string
	}{
		{
			name: "Python 3.13 ARM64 MRS followed by ADD",
			code: []byte{
				// MRS X0, TPIDR_EL0  (S3_3_C13_C0_2)
				0x40, 0xd0, 0x3b, 0xd5,
				// ADD X0, X0, #0x10
				0x00, 0x40, 0x00, 0x91,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x1000,
			expected: 16, // offset 0x10
		},
		{
			name: "Python 3.13 ARM64 MRS followed by LDR",
			code: []byte{
				// MRS X1, TPIDR_EL0
				0x41, 0xd0, 0x3b, 0xd5,
				// LDR X0, [X1, #0x20]
				0x20, 0x10, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x2000,
			expected: 32, // offset 0x20
		},
		{
			name: "Python 3.13 ARM64 MRS with intermediate register",
			code: []byte{
				// MRS X2, TPIDR_EL0
				0x42, 0xd0, 0x3b, 0xd5,
				// ADD X3, X2, #0x50
				0x43, 0x40, 0x01, 0x91,
				// LDR X0, [X3, #0x8]
				0x60, 0x04, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x3000,
			expected: 80, // offset 0x50 from ADD
		},
		{
			name: "Python 3.13 ARM64 MRS with multiple operations",
			code: []byte{
				// MRS X8, TPIDR_EL0
				0x48, 0xd0, 0x3b, 0xd5,
				// ADD X8, X8, #0x100
				0x08, 0x01, 0x04, 0x91,
				// LDR X0, [X8]
				0x00, 0x01, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x4000,
			expected: 256, // offset 0x100
		},
		{
			name: "no MRS TPIDR_EL0 found",
			code: []byte{
				// MRS X0, SP_EL0 (different system register)
				0x00, 0x41, 0x38, 0xd5,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x1000,
			expectedError: "could not find MRS TPIDR_EL0 instruction",
		},
		{
			name: "MRS found but no matching ADD/LDR",
			code: []byte{
				// MRS X0, TPIDR_EL0
				0x40, 0xd0, 0x3b, 0xd5,
				// MOV X1, X0 (not ADD or LDR with offset)
				0x01, 0x00, 0x00, 0xaa,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x2000,
			expectedError: "found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset",
		},
		{
			name: "offset too large (out of valid range)",
			code: []byte{
				// MRS X0, TPIDR_EL0
				0x40, 0xd0, 0x3b, 0xd5,
				// ADD X0, X0, #0x1000 (too large, outside valid range < 0x1000)
				0x00, 0x00, 0x40, 0x91,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x3000,
			expectedError: "found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset",
		},
		{
			name:          "empty code",
			code:          []byte{},
			baseAddr:      0x1000,
			expectedError: "could not find MRS TPIDR_EL0 instruction",
		},
		{
			name: "LDR with immediate offset 0x18",
			code: []byte{
				// MRS X10, TPIDR_EL0
				0x4a, 0xd0, 0x3b, 0xd5,
				// LDR X9, [X10, #0x18]
				0x49, 0x0d, 0x40, 0xf9,
				// MOV X0, X9
				0xe0, 0x03, 0x09, 0xaa,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x5000,
			expected: 24, // offset 0x18
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			offset, err := ExtractTLSOffset(td.code, td.baseAddr, nil)
			if td.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), td.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, td.expected, offset)
			}
		})
	}
}

func TestDecodeImmediatePostIndex(t *testing.T) {
	decodeOneMem := func(t *testing.T, code []byte) aa.MemImmediate {
		t.Helper()
		inst, err := aa.Decode(code)
		require.NoError(t, err)
		require.Equal(t, aa.LDR, inst.Op)
		mem, ok := inst.Args[1].(aa.MemImmediate)
		require.True(t, ok, "expected MemImmediate operand")
		return mem
	}

	testdata := []struct {
		name    string
		code    []byte
		wantVal int64
		wantOK  bool
	}{
		{
			// LDR X0, [X1], #8
			name:    "post-index positive offset",
			code:    []byte{0x20, 0x84, 0x40, 0xF8},
			wantVal: 8,
			wantOK:  true,
		},
		{
			// LDR X0, [X1, #32]
			name:    "offset mode",
			code:    []byte{0x20, 0x10, 0x40, 0xF9},
			wantVal: 32,
			wantOK:  true,
		},
		{
			// LDR X0, [X1, #16]!
			name:    "pre-index mode",
			code:    []byte{0x20, 0x0C, 0x41, 0xF8},
			wantVal: 16,
			wantOK:  true,
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			mem := decodeOneMem(t, td.code)
			// Must not panic.
			val, ok := DecodeImmediate(mem)
			require.Equal(t, td.wantOK, ok)
			if td.wantOK {
				assert.Equal(t, td.wantVal, val)
			}
		})
	}
}

func TestExtractTLSOffsetPostIndexLDR(t *testing.T) {
	code := []byte{
		0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
		0x20, 0x84, 0x40, 0xf8, // LDR X0, [X1], #8  (post-index — must not panic)
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	offset, err := ExtractTLSOffset(code, 0x1000, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(8), offset)
}

func TestExtractTLSDESCOffset(t *testing.T) {
	// Bytes for ADRP+ADD+BLR. baseAddr=0x1000, ADRP at offset 4 (instrAddr=0x1004).
	//   page(0x1004) = 0x1000, PCRel = 0x2000 -> pageAddr = 0x3000
	//   ADD imm = 0x20 -> tlsdescAddr = 0x3020
	//
	// ADRP X0, +0x2000 pages (PCRel=0x2000 -> 0xD0000000 LE)
	// ADD  X0, X0, #0x20            (0x91008000 LE)
	// BLR  X2                       (0xD63F0040 LE)
	code := []byte{
		0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
		0x00, 0x00, 0x00, 0xd0, // ADRP X0, #0x2000-pages (result=0x3000 at instrAddr=0x1004)
		0x00, 0x80, 0x00, 0x91, // ADD X0, X0, #0x20
		0x40, 0x00, 0x3f, 0xd6, // BLR X2
	}

	const wantTLSDESCAddr = uint64(0x3020)
	const wantOffset = int32(0x18)

	// Verify that extractTLSDESCOffset finds the right GOT entry address and calls lookupFn.
	gotAddr := uint64(0)
	lookup := func(addr uint64) (int64, error) {
		gotAddr = addr
		return int64(wantOffset), nil
	}
	offset, err := extractTLSDESCOffset(code, 0x1000, lookup)
	require.NoError(t, err)
	assert.Equal(t, wantOffset, offset)
	assert.Equal(t, wantTLSDESCAddr, gotAddr)

	// Verify that a failing lookup falls through gracefully.
	_, err = extractTLSDESCOffset(code, 0x1000, func(uint64) (int64, error) {
		return 0, fmt.Errorf("no reloc")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "TLSDESC pattern")
}

func TestExtractTLSOffsetTLSDESCFallback(t *testing.T) {
	// Full ExtractTLSOffset integration: MRS with no direct ADD/LDR should fall
	// back to the TLSDESC scan when ef is non-nil (stubbed via the lookupFn path).
	code := []byte{
		0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
		0x00, 0x00, 0x00, 0xd0, // ADRP X0, (result=0x3000 at instrAddr=0x1004)
		0x00, 0x80, 0x00, 0x91, // ADD X0, X0, #0x20 → tlsdescAddr = 0x3020
		0x40, 0x00, 0x3f, 0xd6, // BLR X2
	}

	// With ef=nil, the TLSDESC fallback is skipped, so we expect error about missing ADD/LDR.
	_, err := ExtractTLSOffset(code, 0x1000, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "found MRS TPIDR_EL0 but no matching ADD/LDR")
}
