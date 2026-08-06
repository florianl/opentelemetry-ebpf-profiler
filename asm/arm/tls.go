// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm // import "go.opentelemetry.io/ebpf-profiler/asm/arm"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// branchTarget represents a branch target to be analyzed
type branchTarget struct {
	addr  uint64
	depth int
}

// ExtractTLSOffset extracts the TLS offset by analyzing ARM64 assembly code.
// It looks for the pattern: MRS Xn, TPIDR_EL0 followed by ADD Xn, Xn, #offset or LDR [Xn, #offset].
func ExtractTLSOffset(code []byte, baseAddr uint64, ef *pfelf.File) (int32, error) {
	const maxDepth = 5
	const maxIterations = 100

	// Work queue for branches to follow
	queue := []branchTarget{{addr: baseAddr, depth: 0}}
	visited := make(map[uint64]bool)

	iterations := 0
	foundMRS := false

	for len(queue) > 0 && iterations < maxIterations {
		iterations++

		// Pop from queue
		current := queue[0]
		queue = queue[1:]

		// Check if already visited or depth exceeded
		if visited[current.addr] || current.depth > maxDepth {
			continue
		}
		visited[current.addr] = true

		var codeToAnalyze []byte
		var codeBaseAddr uint64

		if current.addr == baseAddr {
			codeToAnalyze = code
			codeBaseAddr = baseAddr
		} else {
			targetCode := make([]byte, 256)
			err := ef.GetRemoteMemory().Read(libpf.Address(current.addr), targetCode)
			if err != nil {
				continue
			}
			codeToAnalyze = targetCode
			codeBaseAddr = current.addr
		}

		var tpReg int

		for offs := 0; offs < len(codeToAnalyze)-4; offs += 4 {
			inst, err := aa.Decode(codeToAnalyze[offs:])
			if err != nil {
				continue
			}

			// Check for MRS Xn, TPIDR_EL0 (system register S3_3_C13_C0_2)
			if inst.Op == aa.MRS && inst.Args[1].String() == "S3_3_C13_C0_2" {
				reg, ok := Xreg2num(inst.Args[0])
				if !ok {
					continue
				}
				tpReg = reg
				foundMRS = true

				// Look ahead for ADD or LDR using this register
				for j := offs + 4; j < len(codeToAnalyze)-4 && j < offs+64; j += 4 {
					nextInst, err := aa.Decode(codeToAnalyze[j:])
					if err != nil {
						continue
					}

					// Check for ADD Xd, Xn, #imm
					if nextInst.Op == aa.ADD {
						destReg, destOk := Xreg2num(nextInst.Args[0])
						srcReg, srcOk := Xreg2num(nextInst.Args[1])
						imm, immOk := DecodeImmediate(nextInst.Args[2])

						if destOk && srcOk && immOk && srcReg == tpReg {
							if imm > 0 && imm < 0x1000 {
								return validateTLSOffset(int32(imm))
							}
							// Track the new register holding TP+offset
							tpReg = destReg
						}
					}

					// Check for LDR Xm, [Xn, #imm]
					if nextInst.Op == aa.LDR {
						// Args[1] is MemImmediate
						if mem, ok := nextInst.Args[1].(aa.MemImmediate); ok {
							baseReg, regOk := Xreg2num(mem.Base)
							imm, immOk := DecodeImmediate(mem)

							if regOk && immOk && baseReg == tpReg {
								if imm > 0 && imm < 0x1000 {
									return validateTLSOffset(int32(imm))
								}
							}
						}
					}
				}
			}

			// Check for unconditional branch and add to queue
			if inst.Op == aa.B {
				if pcrel, ok := inst.Args[0].(aa.PCRel); ok {
					targetAddr := int64(codeBaseAddr) + int64(offs) + int64(pcrel)

					if targetAddr > 0 && targetAddr < 0x100000000 && !visited[uint64(targetAddr)] {
						queue = append(queue, branchTarget{
							addr:  uint64(targetAddr),
							depth: current.depth + 1,
						})
					}
				}
			}
		}

		// If we found MRS in this block but no valid offset, continue to next block
		if foundMRS {
			// We found MRS but didn't return, meaning no valid offset was found in this block
			// Continue with other blocks in the queue
			continue
		}
	}

	if !foundMRS {
		return 0, fmt.Errorf("could not find MRS TPIDR_EL0 instruction")
	}

	// MRS found but no direct ADD/LDR offset. Fall back to the TLSDESC pattern used
	// by shared libraries.
	// The TLS offset is stored as the addend in the R_AARCH64_TLSDESC relocation.
	if ef != nil {
		if offset, err := extractTLSDESCOffset(code, baseAddr, ef.GetTLSDESCOffset); err == nil {
			return offset, nil
		}
	}

	return 0, fmt.Errorf("found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset")
}

// extractTLSDESCOffset scans the code for the TLSDESC calling sequence used in
// shared libraries:
//
//	ADRP Rpage, label
//	ADD  Rdesc, Rpage, #imm
//	BLR  Rresolver
//
// and resolves the TLS offset via lookupFn. Only the ADRP+ADD pair is needed:
// it uniquely identifies the TLSDESC GOT entry whose R_AARCH64_TLSDESC relocation
// addend is the TLS offset the resolver would return at runtime.
func extractTLSDESCOffset(code []byte, baseAddr uint64,
	lookupFn func(uint64) (int64, error)) (int32, error) {
	for offs := 0; offs < len(code)-4; offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil || inst.Op != aa.ADRP {
			continue
		}
		pageReg, pageOk := Xreg2num(inst.Args[0])
		if !pageOk {
			continue
		}
		pcrel, pcOk := inst.Args[1].(aa.PCRel)
		if !pcOk {
			continue
		}
		instrAddr := baseAddr + uint64(offs)
		// ADRP result: page-align the instruction address and add the page-relative offset.
		pageAddr := (instrAddr &^ uint64(0xFFF)) + uint64(int64(pcrel))

		// Scan ahead for ADD Rdesc, Rpage, #imm to compute the TLSDESC GOT entry address.
		for j := offs + 4; j < len(code)-4 && j < offs+32; j += 4 {
			nextInst, err := aa.Decode(code[j:])
			if err != nil {
				continue
			}
			if nextInst.Op != aa.ADD {
				continue
			}
			srcReg, srcOk := Xreg2num(nextInst.Args[1])
			imm, immOk := DecodeImmediate(nextInst.Args[2])
			if !srcOk || !immOk || srcReg != pageReg || imm <= 0 {
				continue
			}
			tlsdescAddr := pageAddr + uint64(imm)
			addend, err := lookupFn(tlsdescAddr)
			if err != nil {
				continue
			}
			return validateTLSOffset(int32(addend))
		}
	}
	return 0, fmt.Errorf("TLSDESC pattern (ADRP+ADD) not found")
}

// validateTLSOffset ensures that the extracted offset is within some boundaries.
func validateTLSOffset(offset int32) (int32, error) {
	// In theory all 32 bits can be used to represent the offset.
	// But usually this is not the case.
	// For more see https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
	if (offset < 0 && offset > -4096) || (offset > 0 && offset < 4096) {
		return offset, nil
	}
	return 0, fmt.Errorf("could not find valid FS-relative MOV instruction")
}
