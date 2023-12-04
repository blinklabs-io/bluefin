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

package miner

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/version"

	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/minio/sha256-simd"
)

type Miner struct {
	Config     *config.Config
	Logger     *logging.Logger
	waitGroup  *sync.WaitGroup
	resultChan chan Result
	doneChan   chan any
	blockData  any
	state      TargetState
}

type TargetState interface {
	ToBytes() ([]byte, error)
	SetNonce([16]byte)
	GetNonce() [16]byte
}

type TargetStateV1 struct {
	Nonce            [16]byte
	BlockNumber      int64
	CurrentHash      []byte
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
}

func (t *TargetStateV1) SetNonce(nonce [16]byte) {
	t.Nonce = nonce
}

func (t *TargetStateV1) GetNonce() [16]byte {
	return t.Nonce
}

func (state *TargetStateV1) MarshalCBOR() ([]byte, error) {
	tmp := cbor.NewConstructor(
		0,
		cbor.IndefLengthList{
			Items: []any{
				state.Nonce,
				state.BlockNumber,
				state.CurrentHash,
				state.LeadingZeros,
				state.DifficultyNumber,
				state.EpochTime,
			},
		},
	)
	return cbor.Encode(&tmp)
}

func (state *TargetStateV1) ToBytes() ([]byte, error) {
	return cbor.Encode(&state)
}

type DifficultyMetrics struct {
	LeadingZeros     int64
	DifficultyNumber int64
}

type Result struct {
	BlockData any
	Nonce     [16]byte
}

func New(
	waitGroup *sync.WaitGroup,
	resultChan chan Result,
	doneChan chan any,
	blockData any,
) *Miner {
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

	profileCfg := config.GetProfile()

	if profileCfg.UseTunaV1 {
		// Create initial state from block data
		blockData := m.blockData.(models.TunaV1State)
		m.state = &TargetStateV1{
			Nonce:            randomNonce(),
			BlockNumber:      blockData.BlockNumber,
			CurrentHash:      blockData.CurrentHash,
			LeadingZeros:     blockData.LeadingZeros,
			DifficultyNumber: blockData.DifficultyNumber,
			EpochTime:        blockData.EpochTime,
		}
	} else {
		panic("profile doesn't have version configured")
	}

	targetHash := m.calculateHash()

	// Check for shutdown
	select {
	case <-m.doneChan:
		return
	default:
		break
	}

	realTimeNow := time.Now().Unix()*1000 - 60000

	var epochTime int64
	var tmpInterlink [][]byte
	if profileCfg.UseTunaV1 {
		blockData := m.blockData.(models.TunaV1State)
		epochTime = blockData.EpochTime + 90000 + realTimeNow - blockData.RealTimeNow
		tmpInterlink = blockData.Interlink
	}

	difficulty := getDifficulty([]byte(targetHash))
	currentInterlink := calculateInterlink(
		targetHash,
		difficulty,
		m.getCurrentDifficulty(),
		tmpInterlink,
	)

	// Construct the new block data
	var postDatum any
	if profileCfg.UseTunaV1 {
		blockData := m.blockData.(models.TunaV1State)
		postDatum = models.TunaV1State{
			BlockNumber:      blockData.BlockNumber + 1,
			CurrentHash:      targetHash,
			LeadingZeros:     blockData.LeadingZeros,
			DifficultyNumber: blockData.DifficultyNumber,
			EpochTime:        epochTime,
			RealTimeNow:      90000 + realTimeNow,
			Extra: []byte(
				fmt.Sprintf("Bluefin %s by Blink Labs", version.GetVersionString()),
			),
			Interlink: currentInterlink,
		}
	} else {
		panic("profile doesn't have version configured")
	}

	// Check for shutdown
	select {
	case <-m.doneChan:
		return
	default:
		break
	}

	// Return the result
	m.resultChan <- Result{BlockData: postDatum, Nonce: m.state.GetNonce()}
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
	var tmpLeadingZeros int64
	var tmpDifficultyNumber int64
	switch v := m.blockData.(type) {
	case models.TunaV1State:
		tmpLeadingZeros = v.LeadingZeros
		tmpDifficultyNumber = v.DifficultyNumber
	default:
		panic("unknown state model type")
	}
	for {
		// Check for shutdown
		select {
		case <-m.doneChan:
			return nil
		default:
			break
		}
		stateBytes, err := m.state.ToBytes()
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
		if metrics.LeadingZeros > tmpLeadingZeros ||
			(metrics.LeadingZeros == tmpLeadingZeros && metrics.DifficultyNumber < tmpDifficultyNumber) {
			return hash2
		}

		// Currently we create a new random nonce
		// Uncomment if we decide to increment the nonce
		// incrementNonce(m.state.Nonce[:])
		m.state.SetNonce(randomNonce())
	}
}

func (m *Miner) getCurrentDifficulty() DifficultyMetrics {
	var tmpLeadingZeros int64
	var tmpDifficultyNumber int64
	switch v := m.blockData.(type) {
	case models.TunaV1State:
		tmpLeadingZeros = v.LeadingZeros
		tmpDifficultyNumber = v.DifficultyNumber
	default:
		panic("unknown state model type")
	}
	return DifficultyMetrics{
		LeadingZeros:     tmpLeadingZeros,
		DifficultyNumber: tmpDifficultyNumber,
	}
}

func getDifficulty(hash []byte) DifficultyMetrics {
	var leadingZeros int64
	var difficultyNumber int64
	for indx, chr := range hash {
		if chr != 0 {
			//
			if (chr & 0x0F) == chr {
				leadingZeros += 1
				difficultyNumber += int64(chr) * 4096
				difficultyNumber += int64(hash[indx+1]) * 16
				difficultyNumber += int64(hash[indx+2]) / 16
				return DifficultyMetrics{
					LeadingZeros:     leadingZeros,
					DifficultyNumber: difficultyNumber,
				}
			} else {
				difficultyNumber += int64(chr) * 256
				difficultyNumber += int64(hash[indx+1])
				return DifficultyMetrics{
					LeadingZeros:     leadingZeros,
					DifficultyNumber: difficultyNumber,
				}
			}
		} else {
			leadingZeros += 2
		}
	}
	return DifficultyMetrics{
		LeadingZeros:     32,
		DifficultyNumber: 0,
	}
}

func calculateInterlink(
	currentHash []byte,
	newDifficulty DifficultyMetrics,
	origDifficulty DifficultyMetrics,
	currentInterlink [][]byte,
) [][]byte {
	interlink := make([][]byte, len(currentInterlink))
	copy(interlink, currentInterlink)

	origHalf := halfDifficultyNumber(origDifficulty)
	currentIndex := 0

	for origHalf.LeadingZeros < newDifficulty.LeadingZeros || (origHalf.LeadingZeros == newDifficulty.LeadingZeros && origHalf.DifficultyNumber > newDifficulty.DifficultyNumber) {
		if currentIndex < len(interlink) {
			interlink[currentIndex] = currentHash
		} else {
			interlink = append(interlink, currentHash)
		}

		origHalf = halfDifficultyNumber(origHalf)
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
