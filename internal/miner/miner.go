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

package miner

import (
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/snek/input/chainsync"
)

type Miner struct {
	Config *config.Config
	Logger *logging.Logger
}

func New() *Miner {
	return &Miner{
		Config: config.GetConfig(),
		Logger: logging.GetLogger(),
	}
}

func (m *Miner) Start() {
	// validatorAddress := m.Config.Genesis.ValidatorAddress
	// validatorUTXOs = GetUTXOsForAddress(events, validatorAddress)

}

// GetUTXOsForAddress filters the TransactionEvent outputs for a given address
func GetUTXOsForAddress(events []chainsync.TransactionEvent, address string) []ledger.TransactionOutput {
	var utxos []ledger.TransactionOutput

	for _, event := range events {
		for _, output := range event.Outputs {
			if output.Address().String() == address {
				utxos = append(utxos, output)
			}
		}
	}

	return utxos
}
