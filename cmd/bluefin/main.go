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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/indexer"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bursa"
)

var cmdlineFlags struct {
	configFile string
}

func main() {
	flag.StringVar(&cmdlineFlags.configFile, "config", "", "path to config file to load")
	flag.Parse()

	// Load config
	cfg, err := config.Load(cmdlineFlags.configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		os.Exit(1)
	}

	// Configure logging
	logging.Setup()
	logger := logging.GetLogger()
	// Sync logger on exit
	defer func() {
		if err := logger.Sync(); err != nil {
			// We don't actually care about the error here, but we have to do something
			// to appease the linter
			return
		}
	}()

	// Setup wallet
	mnemonic := cfg.Wallet.Mnemonic
	if mnemonic == "" {
		// Read seed.txt if it exists
		if data, err := os.ReadFile("seed.txt"); err == nil {
			logger.Infof("read mnemonic from seed.txt")
			mnemonic = string(data)
		} else if errors.Is(err, os.ErrNotExist) {
			mnemonic, err = bursa.NewMnemonic()
			if err != nil {
				panic(err)
			}
			// Write seed.txt
			// WARNING: this will clobber existing files
			f, err := os.Create("seed.txt")
			if err != nil {
				panic(err)
			}
			l, err := f.WriteString(mnemonic)
			logger.Debugf("wrote %d bytes to seed.txt", l)
			if err != nil {
				f.Close()
				panic(err)
			}
			err = f.Close()
			if err != nil {
				panic(err)
			}
			logger.Infof("wrote generated mnemonic to seed.txt")
		} else {
			panic(err)
		}
	}
	rootKey, err := bursa.GetRootKeyFromMnemonic(mnemonic)
	if err != nil {
		panic(err)
	}
	accountKey := bursa.GetAccountKey(rootKey, 0)
	addr := bursa.GetAddress(accountKey, cfg.Indexer.Network, 0)
	logger.Infof("loaded mnemonic for address: %s", addr.String())

	// Start indexer
	logger.Infof("starting indexer on %s", cfg.Indexer.Network)
	if err := indexer.GetIndexer().Start(); err != nil {
		logger.Fatalf("failed to start indexer: %s", err)
	}

	// Wait forever
	select {}
}
