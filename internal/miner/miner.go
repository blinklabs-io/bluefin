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
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/blinklabs-io/bluefin/internal/common"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/version"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/minio/sha256-simd"
)

type Miner struct {
	Config     *config.Config
	Logger     *logging.Logger
	waitGroup  *sync.WaitGroup
	resultChan chan Result
	doneChan   chan any
	blockData  common.BlockData
	state      *State
}

type State struct {
	Nonce            [16]byte
	BlockNumber      int64
	CurrentHash      []byte
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
}

type DifficultyMetrics struct {
	LeadingZeros     int64
	DifficultyNumber int64
}

type Result struct {
	BlockData common.BlockData
	Nonce     [16]byte
}

func New(waitGroup *sync.WaitGroup, resultChan chan Result, doneChan chan any, blockData common.BlockData) *Miner {
	return &Miner{
		Config:     config.GetConfig(),
		Logger:     logging.GetLogger(),
		waitGroup:  waitGroup,
		resultChan: resultChan,
		doneChan:   doneChan,
		blockData:  blockData,
	}
}

func (m *Miner) Start() {
	defer m.waitGroup.Done()

	// TODO: check on m.doneChan and exit

	// Create initial state from block data
	m.state = &State{
		Nonce:            randomNonce(),
		BlockNumber:      m.blockData.BlockNumber,
		CurrentHash:      m.blockData.TargetHash,
		LeadingZeros:     m.blockData.LeadingZeros,
		DifficultyNumber: m.blockData.DifficultyNumber,
		EpochTime:        m.blockData.EpochTime,
	}

	targetHash := m.calculateHash()

	// Check for shutdown
	select {
	case <-m.doneChan:
		return
	default:
		break
	}

	fmt.Printf("Nonce: %x, Hash with leading zeros: %x\n", m.state.Nonce, targetHash)

	realTimeNow := time.Now().Unix()*1000 - 60000

	epochTime := m.state.DifficultyNumber + 90000 + realTimeNow - m.state.EpochTime

	// TODO: Find where does it come from in the original code
	// m.state.fields[7] as string[]
	stateInterlink := [][]byte{
		[]byte("BlinkLabs"),
		[]byte("BlueFin"),
	}

	difficulty := getDifficulty([]byte(targetHash))
	currentInterlink := calculateInterlink(targetHash, difficulty, DifficultyMetrics{LeadingZeros: m.state.LeadingZeros, DifficultyNumber: m.state.DifficultyNumber}, stateInterlink)

	// Construct the new block data
	postDatum := common.BlockData{
		BlockNumber:      m.state.BlockNumber + 1,
		TargetHash:       targetHash,
		LeadingZeros:     difficulty.LeadingZeros,
		DifficultyNumber: difficulty.DifficultyNumber,
		EpochTime:        epochTime,
		RealTimeNow:      90000 + realTimeNow,
		Message:          []byte(fmt.Sprintf("Bluefin %s by Blink Labs", version.GetVersionString())),
		Interlink:        currentInterlink,
	}

	// Check for shutdown
	select {
	case <-m.doneChan:
		return
	default:
		break
	}

	// Return the result
	m.resultChan <- Result{BlockData: postDatum, Nonce: m.state.Nonce}
}

func randomNonce() [16]byte {
	var ret [16]byte
	// This will never return an error
	_, _ = rand.Read(ret[:])
	return ret
}

//nolint:unused
func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		if nonce[i] < 255 {
			nonce[i]++
			break
		}
		nonce[i] = 0
	}
}

func (m *Miner) calculateHash() []byte {
	for {
		// Check for shutdown
		select {
		case <-m.doneChan:
			return nil
		default:
			break
		}
		stateBytes, err := stateToBytes(m.state)
		if err != nil {
			logging.GetLogger().Error(err)
			return nil
		}

		// Hash it once
		hasher := sha256.New()
		hasher.Write(stateBytes)
		hash := hasher.Sum(nil)

		// And hash it again
		hasher2 := sha256.New()
		hasher2.Write(hash)
		hash2 := hasher2.Sum(nil)

		// Get the difficulty metrics for the hash
		metrics := getDifficulty(hash2)

		// Check the condition
		if metrics.LeadingZeros > m.state.LeadingZeros || (metrics.LeadingZeros == m.state.LeadingZeros && metrics.DifficultyNumber < 2) {
			return hash2
		}

		// Currently we create a new random nonce
		// Uncomment if we decide to increment the nonce
		// incrementNonce(m.state.Nonce[:])

		m.state.Nonce = randomNonce()
	}
}

func stateToBytes(state *State) ([]byte, error) {
	tmp := []byte{
		// Tag 121 (alternative 0)
		0xd8,
		0x79,
		// Indefinite length array
		0x9f,
	}
	for _, val := range []any{
		state.Nonce,
		state.BlockNumber,
		state.CurrentHash,
		state.LeadingZeros,
		state.DifficultyNumber,
		state.EpochTime,
	} {
		data, err := cbor.Encode(&val)
		if err != nil {
			return nil, err
		}
		tmp = append(tmp, data...)
	}
	tmp = append(
		tmp,
		[]byte{
			// End indefinite length array
			0xff,
		}...,
	)
	return tmp, nil
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

func calculateInterlink(currentHash []byte, a DifficultyMetrics, b DifficultyMetrics, currentInterlink [][]byte) [][]byte {
	interlink := make([][]byte, len(currentInterlink))
	copy(interlink, currentInterlink)

	bHalf := halfDifficultyNumber(b)
	currentIndex := 0

	for bHalf.LeadingZeros < a.LeadingZeros || (bHalf.LeadingZeros == a.LeadingZeros && bHalf.DifficultyNumber > a.DifficultyNumber) {
		if currentIndex < len(interlink) {
			interlink[currentIndex] = currentHash
		} else {
			interlink = append(interlink, currentHash)
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
