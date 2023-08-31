// Copyright 2023 Blink Labs, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Storage StorageConfig `yaml:"storage"`
	Indexer IndexerConfig `yaml:"indexer"`
	Wallet  WalletConfig  `yaml:"wallet"`
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics"`
	Genesis GenesisConfig `yaml:"genesis"`
	Debug   DebugConfig   `yaml:"debug"`
}

type IndexerConfig struct {
	Network       string `yaml:"network" envconfig:"INDEXER_NETWORK"`
	NetworkMagic  uint32 `yaml:"networkMagic" envconfig:"INDEXER_NETWORK_MAGIC"`
	Address       string `yaml:"address" envconfig:"INDEXER_TCP_ADDRESS"`
	SocketPath    string `yaml:"socketPath" envconfig:"INDEXER_SOCKET_PATH"`
	ScriptAddress string `yaml:"scriptAddress" envconfig:"INDEXER_SCRIPT_ADDRESS"`
	InterceptHash string `yaml:"interceptHash" envconfig:"INDEXER_INTERCEPT_HASH"`
	InterceptSlot uint64 `yaml:"interceptSlot" envconfig:"INDEXER_INTERCEPT_SLOT"`
}

type StorageConfig struct {
	Directory string `yaml:"dir" envconfig:"STORAGE_DIR"`
}

type WalletConfig struct {
	Mnemonic string `yaml:"mnemonic" envconfig:"MNEMONIC"`
}

type LoggingConfig struct {
	Healthchecks bool   `yaml:"healthchecks" envconfig:"LOGGING_HEALTHCHECKS"`
	Level        string `yaml:"level" envconfig:"LOGGING_LEVEL"`
}

type MetricsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"METRICS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"METRICS_LISTEN_PORT"`
}

type GenesisConfig struct {
	Validator        string `json:"validator"`
	ValidatorHash    string `json:"validatorHash"`
	ValidatorAddress string `json:"validatorAddress"`
	BootstrapHash    string `json:"boostrapHash"`
	Datum            string `json:"datum"`
	OutRef           OutRef `json:"outRef"`
}

type OutRef struct {
	TxHash string `json:"txHash"`
	Index  int    `json:"index"`
}

type DebugConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DEBUG_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"DEBUG_PORT"`
}

// Singleton config instance with default values
var globalConfig = &Config{
	Logging: LoggingConfig{
		Level:        "info",
		Healthchecks: false,
	},
	Debug: DebugConfig{
		ListenAddress: "localhost",
		ListenPort:    0,
	},
	Metrics: MetricsConfig{
		ListenAddress: "",
		ListenPort:    8081,
	},
	Indexer: IndexerConfig{
		Network:       "mainnet",
		ScriptAddress: "addr1wynelppvx0hdjp2tnc78pnt28veznqjecf9h3wy4edqajxsg7hwsc",
		InterceptHash: "b019548e41b55ae702fee37d8b9ae716c978712c02bc4862ba13db6602e5af72",
		InterceptSlot: 101511155,
	},
	Storage: StorageConfig{
		// TODO: pick a better location
		Directory: "./.bluefin",
	},
}

func Load(configFile string) (*Config, error) {
	// Load config file as YAML if provided
	if configFile != "" {
		buf, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %s", err)
		}
		err = yaml.Unmarshal(buf, globalConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing config file: %s", err)
		}
	}
	// Load config values from environment variables
	// We use "dummy" as the app name here to (mostly) prevent picking up env
	// vars that we hadn't explicitly specified in annotations above
	err := envconfig.Process("dummy", globalConfig)
	if err != nil {
		return nil, fmt.Errorf("error processing environment: %s", err)
	}
	return globalConfig, nil
}

// GetConfig returns the global config instance
func GetConfig() *Config {
	return globalConfig
}
