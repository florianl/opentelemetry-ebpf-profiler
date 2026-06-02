// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/beam"
	"go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"
	golang "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/interpreter/golabels"
	"go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"
	"go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"
	"go.opentelemetry.io/ebpf-profiler/interpreter/perl"
	"go.opentelemetry.io/ebpf-profiler/interpreter/php"
	"go.opentelemetry.io/ebpf-profiler/interpreter/python"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
)

const (
	// 1TB of executable address space
	MaxArgMapScaleFactor = 8

	// probabilisticThresholdMax mirrors probabilisticThresholdMax.
	// Defined here to avoid an import cycle (tracer imports collector/config).
	probabilisticThresholdMax = 100
)

// ErrorMode controls how the profiler receiver handles startup errors.
type ErrorMode string

const (
	// IgnoreError means startup errors are logged but not returned to the collector.
	IgnoreError ErrorMode = "ignore"
	// PropagateError means startup errors are returned to the collector (default).
	PropagateError ErrorMode = "propagate"
)

func (e *ErrorMode) UnmarshalText(text []byte) error {
	str := ErrorMode(strings.ToLower(string(text)))
	switch str {
	case IgnoreError, PropagateError:
		*e = str
		return nil
	default:
		return fmt.Errorf("unknown error mode %q", str)
	}
}

// Config is the configuration for the collector.
type Config struct {
	ReporterInterval       time.Duration                  `mapstructure:"reporter_interval"`
	ReporterJitter         float64                        `mapstructure:"reporter_jitter"`
	MonitorInterval        time.Duration                  `mapstructure:"monitor_interval"`
	SamplesPerSecond       int                            `mapstructure:"samples_per_second"`
	ProbabilisticInterval  time.Duration                  `mapstructure:"probabilistic_interval"`
	ProbabilisticThreshold uint                           `mapstructure:"probabilistic_threshold"`
	Interpreters           map[interpreter.ID]interpreter.Config `mapstructure:"-"`
	ClockSyncInterval      time.Duration                  `mapstructure:"clock_sync_interval"`
	SendErrorFrames        bool                           `mapstructure:"send_error_frames"`
	SendIdleFrames         bool                           `mapstructure:"send_idle_frames"`
	VerboseMode            bool                           `mapstructure:"verbose_mode"`
	OffCPUThreshold        float64                        `mapstructure:"off_cpu_threshold"`
	IncludeEnvVars         string                         `mapstructure:"include_env_vars"`
	ProbeLinks             []string                       `mapstructure:"probe_links"`
	LoadProbe              bool                           `mapstructure:"load_probe"`
	MapScaleFactor         uint                           `mapstructure:"map_scale_factor"`
	BPFVerifierLogLevel    uint                           `mapstructure:"bpf_verifier_log_level"`
	NoKernelVersionCheck   bool                           `mapstructure:"no_kernel_version_check"`
	MaxGRPCRetries         uint32                         `mapstructure:"max_grpc_retries"`
	MaxRPCMsgSize          int                            `mapstructure:"max_rpc_msg_size"`
	BPFFSRoot              string                         `mapstructure:"bpf_fs_root"`
	ErrorMode              ErrorMode                      `mapstructure:"error_mode"`
	OBIProcessCtx          bool                           `mapstructure:"obi_process_ctx"`
}

// Compile-time checks that Config satisfies the confmap interfaces.
var _ confmap.Unmarshaler = (*Config)(nil)

// interpreterRegistry maps interpreter IDs (which equal the YAML/CLI key names)
// to constructors that return a *ConcreteConfig suitable for confmap.Unmarshal.
var interpreterRegistry = map[interpreter.ID]func() any{
	interpreter.PythonID:  func() any { return &python.Config{} },
	interpreter.PerlID:    func() any { return &perl.Config{} },
	interpreter.PHPID:     func() any { return &php.Config{} },
	interpreter.HotspotID: func() any { return &hotspot.Config{} },
	interpreter.RubyID:    func() any { return &ruby.Config{} },
	interpreter.V8ID:      func() any { return &nodev8.Config{} },
	interpreter.DotnetID:  func() any { return &dotnet.Config{} },
	interpreter.GoID:      func() any { return &golang.Config{} },
	interpreter.LabelsID:  func() any { return &golabels.Config{} },
	interpreter.BEAMID:    func() any { return &beam.Config{} },
}

// NewInterpreterConfig returns a zero-value typed config for the given interpreter ID.
// Returns (nil, false) if the ID is unknown.
func NewInterpreterConfig(id interpreter.ID) (interpreter.Config, bool) {
	newFn, ok := interpreterRegistry[id]
	if !ok {
		return nil, false
	}
	return reflect.ValueOf(newFn()).Elem().Interface(), true
}

// Unmarshal implements confmap.Unmarshaler. It handles the interpreters section
// manually so each key maps to its own typed config struct.
func (cfg *Config) Unmarshal(componentParser *confmap.Conf) error {
	if componentParser == nil {
		return nil
	}

	// Decode all fields except Interpreters (tagged mapstructure:"-") normally.
	if err := componentParser.Unmarshal(cfg, confmap.WithIgnoreUnused()); err != nil {
		return err
	}

	interpretersSection, err := componentParser.Sub("interpreters")
	if err != nil {
		return err
	}

	// If the section is absent or empty, keep the default set by the factory.
	if len(interpretersSection.ToStringMap()) == 0 {
		return nil
	}

	cfg.Interpreters = make(map[interpreter.ID]interpreter.Config)
	for keyStr := range interpretersSection.ToStringMap() {
		id := interpreter.ID(keyStr)
		newFn, ok := interpreterRegistry[id]
		if !ok {
			return fmt.Errorf("unknown interpreter %q", keyStr)
		}

		sub, err := interpretersSection.Sub(keyStr)
		if err != nil {
			return err
		}

		cfgPtr := newFn()
		if err = sub.Unmarshal(cfgPtr); err != nil {
			return fmt.Errorf("error reading settings for interpreter %q: %w", keyStr, err)
		}

		cfg.Interpreters[id] = reflect.ValueOf(cfgPtr).Elem().Interface()
	}

	return nil
}

// Validate validates the config.
// This is automatically called by the config parser as it implements the xconfmap.Validator interface.
func (cfg *Config) Validate() error {
	if cfg.ErrorMode != IgnoreError && cfg.ErrorMode != PropagateError {
		return fmt.Errorf("unknown error mode %q", cfg.ErrorMode)
	}

	if cfg.SamplesPerSecond < 1 {
		return fmt.Errorf("invalid sampling frequency: %d", cfg.SamplesPerSecond)
	}

	if cfg.MapScaleFactor > MaxArgMapScaleFactor {
		return fmt.Errorf(
			"eBPF map scaling factor %d exceeds limit (max: %d)",
			cfg.MapScaleFactor, MaxArgMapScaleFactor,
		)
	}

	if cfg.BPFVerifierLogLevel > 2 {
		return fmt.Errorf("invalid eBPF verifier log level: %d", cfg.BPFVerifierLogLevel)
	}

	if cfg.ProbabilisticInterval < 1*time.Minute || cfg.ProbabilisticInterval > 5*time.Minute {
		return errors.New(
			"invalid argument for probabilistic-interval: use " +
				"a duration between 1 and 5 minutes",
		)
	}

	if cfg.ProbabilisticThreshold < 1 ||
		cfg.ProbabilisticThreshold > probabilisticThresholdMax {
		return fmt.Errorf(
			"invalid argument for probabilistic-threshold. Value "+
				"should be between 1 and %d",
			probabilisticThresholdMax,
		)
	}

	if cfg.OffCPUThreshold < 0.0 || cfg.OffCPUThreshold > 1.0 {
		return errors.New(
			"invalid argument for off-cpu-threshold. The value " +
				"should be in the range [0..1]. 0 disables off-cpu profiling")
	}

	if cfg.ReporterJitter < 0.0 || cfg.ReporterJitter > 1.0 {
		return errors.New(
			"invalid argument for reporter-jitter. The value " +
				"should be in the range [0..1]. 0 disables jitter")
	}

	if !cfg.NoKernelVersionCheck {
		major, minor, patch, err := linux.GetCurrentKernelVersion()
		if err != nil {
			return fmt.Errorf("failed to get kernel version: %v", err)
		}

		var minMajor, minMinor uint32
		minMajor, minMinor = 5, 10
		if major < minMajor || (major == minMajor && minor < minMinor) {
			return fmt.Errorf("host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
		}
	}

	return nil
}

// AllInterpretersConfig returns a map with all interpreters enabled, using their typed configs.
func AllInterpretersConfig() map[interpreter.ID]interpreter.Config {
	cfg := make(map[interpreter.ID]interpreter.Config, len(interpreterRegistry))
	for id := range interpreterRegistry {
		cfg[id], _ = NewInterpreterConfig(id)
	}
	return cfg
}
