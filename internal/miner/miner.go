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
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/minio/sha256-simd"
)

type Miner struct {
	Config *config.Config
	Logger *logging.Logger
}

type State struct {
	Nonce            int
	BlockNumber      int
	CurrentHash      int
	LeadingZeros     string
	DifficultyNumber int
	EpochTime        int
}

func New() *Miner {
	return &Miner{
		Config: config.GetConfig(),
		Logger: logging.GetLogger(),
	}
}

func (m *Miner) Start() error {
	// TODO add real state
	state := State{
		Nonce:            0,
		BlockNumber:      1,
		CurrentHash:      1234567890,
		LeadingZeros:     "0xabcdef",
		DifficultyNumber: 1,
		EpochTime:        1627890123,
	}

	hash, nonce := calculateHash(state)
	fmt.Printf("Hash with leading zeros: %s\n", hash)
	fmt.Printf("Nonce: %d\n", nonce)
	return nil
}

func calculateHash(state State) (string, int) {
	nonce := state.Nonce
	difficulty := state.DifficultyNumber

	for {
		// Construct the input using the state fields and nonce
		input := fmt.Sprintf("%x%d%d%x%d%d",
			nonce,
			state.BlockNumber,
			state.CurrentHash,
			state.LeadingZeros,
			state.DifficultyNumber,
			state.EpochTime,
		)

		// Calculate the hash
		hasher := sha256.New()
		hasher.Write([]byte(input))
		hash := hasher.Sum(nil)

		// Convert the hash to a hexadecimal string
		hashStr := hex.EncodeToString(hash)

		// Check if the hash has the required number of leading zeros
		if strings.HasPrefix(hashStr, strings.Repeat("00", difficulty)) {
			return hashStr, nonce
		}

		nonce++
	}
}
