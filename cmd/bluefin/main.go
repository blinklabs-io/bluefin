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

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/indexer"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/version"
	"github.com/blinklabs-io/bluefin/internal/wallet"
)

var cmdlineFlags struct {
	configFile string
	debug      bool
}

func slogPrintf(format string, v ...any) {
	slog.Info(fmt.Sprintf(format, v...))
}

func main() {
	flag.StringVar(
		&cmdlineFlags.configFile,
		"config",
		"",
		"path to config file to load",
	)
	flag.BoolVar(
		&cmdlineFlags.debug,
		"debug",
		false,
		"enable debug logging",
	)
	flag.Parse()

	// Load config
	cfg, err := config.Load(cmdlineFlags.configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		os.Exit(1)
	}

	// Configure logger
	logging.Configure()
	logger := logging.GetLogger()
	slog.SetDefault(logger)

	slog.Info(
		fmt.Sprintf("bluefin %s started", version.GetVersionString()),
	)

	// Configure max processes with our logger wrapper, toss undo func
	_, err = maxprocs.Set(maxprocs.Logger(slogPrintf))
	if err != nil {
		// If we hit this, something really wrong happened
		slog.Error(err.Error())
		os.Exit(1)
	}

	// Load storage
	if err := storage.GetStorage().Load(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to load storage: %s", err),
		)
		os.Exit(1)
	}

	// Setup wallet
	wallet.Setup()
	bursa := wallet.GetWallet()
	slog.Info(
		"loaded mnemonic for address: " + bursa.PaymentAddress,
	)

	// Fake Tx
	//tx.SendTx([]byte("foo"))

	// Start indexer
	slog.Info(
		"starting indexer on " + cfg.Network,
	)
	if err := indexer.GetIndexer().Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start indexer: %s", err),
		)
		os.Exit(1)
	}

	// Wait forever
	select {}
}
