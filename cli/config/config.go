package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WindowSeconds int         `yaml:"window_seconds"`
	Rules         RulesConfig `yaml:"rules"`
}

type RulesConfig struct {
	PortScan        PortScanConfig        `yaml:"port_scan"`
	HostScan        HostScanConfig        `yaml:"host_scan"`
	SynFlood        SynFloodConfig        `yaml:"syn_flood"`
	AckFlood        AckFloodConfig        `yaml:"ack_flood"`
	UdpFlood        UdpFloodConfig        `yaml:"udp_flood"`
	ConnectionBurst ConnectionBurstConfig `yaml:"connection_burst"`
	SuspiciousFlags SuspiciousFlagsConfig `yaml:"suspicious_flags"`
}

type PortScanConfig struct {
	Enabled     bool `yaml:"enabled"`
	UniquePorts int  `yaml:"unique_ports"`
}

type HostScanConfig struct {
	Enabled     bool `yaml:"enabled"`
	UniqueHosts int  `yaml:"unique_hosts"`
}

type SynFloodConfig struct {
	Enabled      bool    `yaml:"enabled"`
	SynPerSecond float64 `yaml:"syn_per_second"`
	SynAckRatio  float64 `yaml:"syn_ack_ratio"`
	MinSynCount  int     `yaml:"min_syn_count"`
}

type AckFloodConfig struct {
	Enabled      bool    `yaml:"enabled"`
	AckPerSecond float64 `yaml:"ack_per_second"`
}

type UdpFloodConfig struct {
	Enabled             bool    `yaml:"enabled"`
	UdpPacketsPerSecond float64 `yaml:"udp_packets_per_second"`
}

type ConnectionBurstConfig struct {
	Enabled      bool    `yaml:"enabled"`
	SynPerSecond float64 `yaml:"syn_per_second"`
}

type SuspiciousFlagsConfig struct {
	Enabled bool `yaml:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		WindowSeconds: 10,
		Rules: RulesConfig{
			PortScan: PortScanConfig{
				Enabled:     true,
				UniquePorts: 20,
			},
			HostScan: HostScanConfig{
				Enabled:     true,
				UniqueHosts: 20,
			},
			SynFlood: SynFloodConfig{
				Enabled:      true,
				SynPerSecond: 500,
				SynAckRatio:  5.0,
				MinSynCount:  50,
			},
			AckFlood: AckFloodConfig{
				Enabled:      true,
				AckPerSecond: 1000,
			},
			UdpFlood: UdpFloodConfig{
				Enabled:             true,
				UdpPacketsPerSecond: 1000,
			},
			ConnectionBurst: ConnectionBurstConfig{
				Enabled:      true,
				SynPerSecond: 500,
			},
			SuspiciousFlags: SuspiciousFlagsConfig{
				Enabled: true,
			},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 10
	}

	return cfg, nil
}
