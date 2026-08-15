package config

import "time"

type Config struct {
	Agent    AgentConfig    `yaml:"agent"`
	Control  ControlConfig  `yaml:"control"`
	Knockd   KnockdConfig   `yaml:"knockd"`
	Firewall FirewallConfig `yaml:"firewall"`
	Storage  StorageConfig  `yaml:"storage"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type AgentConfig struct {
	ID string `yaml:"id"`
}

type ControlConfig struct {
	Endpoint string        `yaml:"endpoint"`
	Token    string        `yaml:"token"`
	Timeout  time.Duration `yaml:"timeout"`
}

type KnockdConfig struct {
	ConfigPath string `yaml:"config"`
	Service    string `yaml:"service"`
}

type FirewallConfig struct {
	Backend string `yaml:"backend"`
}

type StorageConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}
