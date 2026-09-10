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
	PortScan         PortScanConfig         `yaml:"port_scan"`
	HostScan         HostScanConfig         `yaml:"host_scan"`
	SynFlood         SynFloodConfig         `yaml:"syn_flood"`
	AckFlood         AckFloodConfig         `yaml:"ack_flood"`
	RstFlood         RstFloodConfig         `yaml:"rst_flood"`
	UdpFlood         UdpFloodConfig         `yaml:"udp_flood"`
	IcmpFlood        IcmpFloodConfig        `yaml:"icmp_flood"`
	DnsFlood         DnsFloodConfig         `yaml:"dns_flood"`
	StealthScan      StealthScanConfig      `yaml:"stealth_scan"`
	ConnectionBurst  ConnectionBurstConfig  `yaml:"connection_burst"`
	SuspiciousFlags  SuspiciousFlagsConfig  `yaml:"suspicious_flags"`
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

type RstFloodConfig struct {
	Enabled      bool    `yaml:"enabled"`
	RstPerSecond float64 `yaml:"rst_per_second"`
}

type UdpFloodConfig struct {
	Enabled             bool    `yaml:"enabled"`
	UdpPacketsPerSecond float64 `yaml:"udp_packets_per_second"`
}

type IcmpFloodConfig struct {
	Enabled          bool    `yaml:"enabled"`
	IcmpPerSecond    float64 `yaml:"icmp_per_second"`
	PingSweepEnabled bool    `yaml:"ping_sweep_enabled"`
	UniqueTargets    int     `yaml:"unique_targets"`
}

type DnsFloodConfig struct {
	Enabled             bool    `yaml:"enabled"`
	DnsPacketsPerSecond float64 `yaml:"dns_packets_per_second"`
	DnsBytesPerSecond   float64 `yaml:"dns_bytes_per_second"`
}

type StealthScanConfig struct {
	Enabled    bool `yaml:"enabled"`
	MinPackets int  `yaml:"min_packets"`
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
			RstFlood: RstFloodConfig{
				Enabled:      true,
				RstPerSecond: 500,
			},
			UdpFlood: UdpFloodConfig{
				Enabled:             true,
				UdpPacketsPerSecond: 1000,
			},
			IcmpFlood: IcmpFloodConfig{
				Enabled:          true,
				IcmpPerSecond:    300,
				PingSweepEnabled: true,
				UniqueTargets:    15,
			},
			DnsFlood: DnsFloodConfig{
				Enabled:             true,
				DnsPacketsPerSecond: 500,
				DnsBytesPerSecond:   500000,
			},
			StealthScan: StealthScanConfig{
				Enabled:    true,
				MinPackets: 3,
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
