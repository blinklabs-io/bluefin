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
	"flag"
	"fmt"
	"os"

	_ "go.uber.org/automaxprocs"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/indexer"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/miner"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
	"github.com/blinklabs-io/bluefin/internal/worker"
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

	// Load storage
	if err := storage.GetStorage().Load(); err != nil {
		logger.Fatalf("failed to load storage: %s", err)
	}

	// Setup wallet
	wallet.Setup()
	bursa := wallet.GetWallet()
	logger.Infof("loaded mnemonic for address: %s", bursa.PaymentAddress)

	// Start indexer
	logger.Infof("starting indexer on %s", cfg.Indexer.Network)
	if err := indexer.GetIndexer().Start(); err != nil {
		logger.Fatalf("failed to start indexer: %s", err)
	}

	// TODO: remove me
	// This should be started by the indexer reaching chain tip
	worker.GetManager().Start(worker.WorkerParams{})

	// Start miner
	logger.Infof("starting miner on %s", cfg.Indexer.Network)
	if err := miner.New().Start(); err != nil {
		logger.Fatalf("failed to start miner: %s", err)
	}

	// Wait forever
	select {}
}
