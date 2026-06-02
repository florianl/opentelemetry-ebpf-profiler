// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreter // import "go.opentelemetry.io/ebpf-profiler/interpreter"

// Config defines the configuration for an interpreter.
type Config any

// Has returns true if the interpreter with the given ID is present in the map.
func Has(m map[ID]Config, id ID) bool {
	_, ok := m[id]
	return ok
}

// IsMapEnabled checks if the given eBPF map should be loaded based on the
// interpreters configuration. The map names used here are the eBPF map names
// (e.g. "py_procs"), which are distinct from the interpreter IDs (e.g. "python").
func IsMapEnabled(mapName string, cfg map[ID]Config) bool {
	switch mapName {
	case "py_procs":
		return Has(cfg, PythonID)
	case "php_procs":
		return Has(cfg, PHPID)
	case "hotspot_procs":
		return Has(cfg, HotspotID)
	case "ruby_procs":
		return Has(cfg, RubyID)
	case "v8_procs":
		return Has(cfg, V8ID)
	case "dotnet_procs":
		return Has(cfg, DotnetID)
	case "beam_procs":
		return Has(cfg, BEAMID)
	case "perl_procs":
		return Has(cfg, PerlID)
	default:
		// Core maps and always-on interpreter maps (go_labels_procs, apm_int_procs)
		// are always loaded.
		return true
	}
}
