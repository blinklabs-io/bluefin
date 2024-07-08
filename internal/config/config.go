// Copyright 2023 Blink Labs Software
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
	"runtime"

	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Storage      StorageConfig `yaml:"storage"`
	Indexer      IndexerConfig `yaml:"indexer"`
	Submit       SubmitConfig  `yaml:"submit"`
	Wallet       WalletConfig  `yaml:"wallet"`
	Worker       WorkerConfig  `yaml:"worker"`
	Logging      LoggingConfig `yaml:"logging"`
	Metrics      MetricsConfig `yaml:"metrics"`
	Debug        DebugConfig   `yaml:"debug"`
	Profile      string        `yaml:"profile" envconfig:"PROFILE"`
	Network      string        `yaml:"network" envconfig:"NETWORK"`
	NetworkMagic uint32
}

type IndexerConfig struct {
	Address       string `yaml:"address"       envconfig:"INDEXER_TCP_ADDRESS"`
	SocketPath    string `yaml:"socketPath"    envconfig:"INDEXER_SOCKET_PATH"`
	ScriptAddress string `yaml:"scriptAddress" envconfig:"INDEXER_SCRIPT_ADDRESS"`
	InterceptHash string `yaml:"interceptHash" envconfig:"INDEXER_INTERCEPT_HASH"`
	InterceptSlot uint64 `yaml:"interceptSlot" envconfig:"INDEXER_INTERCEPT_SLOT"`
}

type SubmitConfig struct {
	Address             string `yaml:"address"      envconfig:"SUBMIT_TCP_ADDRESS"`
	SocketPath          string `yaml:"socketPath"   envconfig:"SUBMIT_SOCKET_PATH"`
	Url                 string `yaml:"url"          envconfig:"SUBMIT_URL"`
	BlockFrostProjectID string `yaml:"blockFrostProjectID"` envconfig:"SUBMIT_BLOCKFROST_PROJECT_ID"`
}

type StorageConfig struct {
	Directory string `yaml:"dir" envconfig:"STORAGE_DIR"`
}

type WalletConfig struct {
	Mnemonic string `yaml:"mnemonic" envconfig:"MNEMONIC"`
}

type WorkerConfig struct {
	Count int `yaml:"count" envconfig:"WORKER_COUNT"`
}

type LoggingConfig struct {
	Healthchecks bool   `yaml:"healthchecks" envconfig:"LOGGING_HEALTHCHECKS"`
	Level        string `yaml:"level"        envconfig:"LOGGING_LEVEL"`
}

type MetricsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"METRICS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"METRICS_LISTEN_PORT"`
}

type DebugConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DEBUG_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"DEBUG_PORT"`
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
	Storage: StorageConfig{
		// TODO: pick a better location
		Directory: "./.bluefin",
	},
	// The default worker config is somewhat conservative: worker count is set
	// to half of the available logical CPUs
	Worker: WorkerConfig{
		Count: runtime.NumCPU() / 2,
	},
	Network: "mainnet",
	Profile: "tuna-v1",
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
	// Populate network magic value
	if err := globalConfig.populateNetworkMagic(); err != nil {
		return nil, err
	}
	// Check specified profile
	if err := globalConfig.validateProfile(); err != nil {
		return nil, err
	}
	// Populate our Indexer startup
	if err := globalConfig.populateIndexer(); err != nil {
		return nil, err
	}
	return globalConfig, nil
}

// GetConfig returns the global config instance
func GetConfig() *Config {
	return globalConfig
}

func (c *Config) populateNetworkMagic() error {
	network := ouroboros.NetworkByName(c.Network)
	if network == ouroboros.NetworkInvalid {
		return fmt.Errorf("unknown network: %s", c.Network)
	}
	c.NetworkMagic = network.NetworkMagic
	return nil
}

func (c *Config) validateProfile() error {
	if _, ok := Profiles[c.Network]; !ok {
		return fmt.Errorf("no profiles defined for network %s", c.Network)
	}
	if _, ok := Profiles[c.Network][c.Profile]; !ok {
		return fmt.Errorf("no profile %s defined for network %s", c.Profile, c.Network)
	}
	return nil
}

func (c *Config) populateIndexer() error {
	profile := Profiles[c.Network][c.Profile]
	c.Indexer.InterceptHash = profile.InterceptHash
	c.Indexer.InterceptSlot = profile.InterceptSlot
	c.Indexer.ScriptAddress = profile.ScriptAddress
	return nil
}
