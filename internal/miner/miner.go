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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/version"
	"github.com/minio/sha256-simd"
)

type BlockData struct {
	BlockNumber      int64
	TargetHash       string
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
	RealTimeNow      int64
	Message          string
	Interlink        [][]byte
}

type Miner struct {
	Config *config.Config
	Logger *logging.Logger
}

type State struct {
	Nonce            int64
	BlockNumber      int64
	CurrentHash      int64
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
}

type DifficultyMetrics struct {
	LeadingZeros     int64
	DifficultyNumber int64
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
		LeadingZeros:     3,
		DifficultyNumber: 1,
		EpochTime:        1627890123,
	}

	hash, nonce := calculateHash(state)
	fmt.Printf("Hash with leading zeros: %s\n", hash)
	fmt.Printf("Nonce: %d\n", nonce)

	realTimeNow := time.Now().Unix()*1000 - 60000

	// TODO prepare things for a new block and clean up
	// Sample values for the new block
	targetHash := hash

	epochTime := state.DifficultyNumber + 90000 + realTimeNow - state.EpochTime
	// TODO: calculate interlink

	// TODO: Find where does it come from in the original code
	// state.fields[7] as string[]
	stateInterlink := [][]byte{
		[]byte("BlinkLabs"),
		[]byte("BlueFin"),
	}

	difficulty := getDifficulty([]byte(hash))
	currentInterlink := calculateInterlink(hash, difficulty, DifficultyMetrics{LeadingZeros: state.LeadingZeros, DifficultyNumber: state.DifficultyNumber}, stateInterlink)

	// Construct the new block data
	postDatum := BlockData{
		BlockNumber:      state.BlockNumber + 1,
		TargetHash:       targetHash,
		LeadingZeros:     1,
		DifficultyNumber: 2,
		EpochTime:        epochTime,
		RealTimeNow:      90000 + realTimeNow,
		Message:          fmt.Sprintf("Bluefin %s by Blink Labs", version.GetVersionString()),
		Interlink:        currentInterlink,
	}
	// Found next datum
	fmt.Printf("Found next datum %+v\n", postDatum)
	return nil
}

func calculateHash(state State) (string, int64) {
	nonce := state.Nonce

	for {
		stateBytes, err := stateToBytes(state)
		if err != nil {
			logging.GetLogger().Error(err)
			return "", nonce
		}

		// Calculate the hash
		hasher := sha256.New()
		hasher.Write(stateBytes)
		hash := hasher.Sum(nil)

		// Get the difficulty metrics for the hash
		metrics := getDifficulty(hash)

		// Check the condition
		if metrics.LeadingZeros > state.LeadingZeros || (metrics.LeadingZeros == state.LeadingZeros && metrics.DifficultyNumber < 2) {
			return hex.EncodeToString(hash), nonce
		}

		nonce++
		state.Nonce = nonce
	}
}

func stateToBytes(state State) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, state); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getDifficulty(hash []byte) DifficultyMetrics {
	var metrics DifficultyMetrics
	for indx, chr := range hash {
		if chr != 0 {
			//
			if (chr & 0x0F) == chr {
				metrics.LeadingZeros += 1
				metrics.DifficultyNumber += int64(chr) * 4096
				metrics.DifficultyNumber += int64(hash[indx+1]) * 16
				metrics.DifficultyNumber += int64(hash[indx+2]) / 16
				return metrics
			} else {
				metrics.DifficultyNumber += int64(chr) * 256
				metrics.DifficultyNumber += int64(hash[indx+1])
				return metrics
			}
		} else {
			metrics.LeadingZeros += 2
		}
	}
	metrics.LeadingZeros = 32
	return metrics
}

func calculateInterlink(currentHash string, a DifficultyMetrics, b DifficultyMetrics, currentInterlink [][]byte) [][]byte {
	hashBytes := []byte(currentHash)

	interlink := make([][]byte, len(currentInterlink))
	copy(interlink, currentInterlink)

	bHalf := halfDifficultyNumber(b)
	currentIndex := 0

	for bHalf.LeadingZeros < a.LeadingZeros || (bHalf.LeadingZeros == a.LeadingZeros && bHalf.DifficultyNumber > a.DifficultyNumber) {
		if currentIndex < len(interlink) {
			interlink[currentIndex] = hashBytes
		} else {
			interlink = append(interlink, hashBytes)
		}

		bHalf = halfDifficultyNumber(bHalf)
		currentIndex++
	}

	return interlink
}

func halfDifficultyNumber(metrics DifficultyMetrics) DifficultyMetrics {
	newA := metrics.DifficultyNumber / 2
	if newA < 4096 {
		return DifficultyMetrics{
			LeadingZeros:     metrics.LeadingZeros + 1,
			DifficultyNumber: newA * 16,
		}
	} else {
		return DifficultyMetrics{
			LeadingZeros:     metrics.LeadingZeros,
			DifficultyNumber: newA,
		}
	}
}
