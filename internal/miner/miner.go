// Copyright 2024 Blink Labs Software
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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/minio/sha256-simd"
)

const (
	DefaultEpochNumber = 2016
	DefaultEpochTarget = 1_209_600_000
)

type Miner struct {
	Config      *config.Config
	waitGroup   *sync.WaitGroup
	resultChan  chan Result
	doneChan    chan any
	blockData   any
	state       TargetState
	hashCounter *atomic.Uint64
	nonceCount  uint8
}

type TargetState interface {
	MarshalCBOR() ([]byte, error)
	SetNonce([16]byte)
	GetNonce() [16]byte
}

type TargetStateV1 struct {
	CurrentHash      []byte
	BlockNumber      int64
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
	Nonce            [16]byte
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
			state.Nonce,
			state.BlockNumber,
			state.CurrentHash,
			state.LeadingZeros,
			state.DifficultyNumber,
			state.EpochTime,
		},
	)
	return cbor.Encode(&tmp)
}

type TargetStateV2 struct {
	MinerCredHash    []byte
	CurrentHash      []byte
	cachedCbor       []byte
	EpochTime        int64
	BlockNumber      int64
	LeadingZeros     int64
	DifficultyNumber int64
	Nonce            [16]byte
}

func (t *TargetStateV2) SetNonce(nonce [16]byte) {
	t.Nonce = nonce
}

func (t *TargetStateV2) GetNonce() [16]byte {
	return t.Nonce
}

func (state *TargetStateV2) MarshalCBOR() ([]byte, error) {
	// Use cached CBOR to generate new CBOR more quickly
	if state.cachedCbor != nil {
		// Replace nonce value in cached CBOR with current nonce
		for i := range 16 {
			state.cachedCbor[4+i] = state.Nonce[i]
		}
		return state.cachedCbor, nil
	}
	// There are different ways we can order the fields for V2, so we need to check which
	profileCfg := config.GetProfile()
	var indefList cbor.IndefLengthList
	if profileCfg.TunaV2OldTargetStateOrder {
		indefList = cbor.IndefLengthList{
			state.Nonce,
			state.MinerCredHash,
			state.EpochTime,
			state.BlockNumber,
			state.CurrentHash,
			state.LeadingZeros,
			state.DifficultyNumber,
		}
	} else {
		indefList = cbor.IndefLengthList{
			state.Nonce,
			state.MinerCredHash,
			state.BlockNumber,
			state.CurrentHash,
			state.LeadingZeros,
			state.DifficultyNumber,
			state.EpochTime,
		}
	}
	tmp := cbor.NewConstructor(
		0,
		indefList,
	)
	cborData, err := cbor.Encode(&tmp)
	if err != nil {
		return nil, err
	}
	state.cachedCbor = make([]byte, len(cborData))
	copy(state.cachedCbor, cborData)
	return cborData, nil
}

type DifficultyMetrics struct {
	LeadingZeros     int64
	DifficultyNumber int64
}

type DifficultyAdjustment struct {
	Numerator   int64
	Denominator int64
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
	hashCounter *atomic.Uint64,
) *Miner {
	return &Miner{
		Config:      config.GetConfig(),
		waitGroup:   waitGroup,
		resultChan:  resultChan,
		doneChan:    doneChan,
		blockData:   blockData,
		hashCounter: hashCounter,
	}
}

func (m *Miner) Start() {
	defer m.waitGroup.Done()

	cfg := config.GetConfig()
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
		// Build miner credential
		userPkh := wallet.PaymentKeyHash()
		minerCredential := cbor.NewConstructor(
			0,
			cbor.IndefLengthList{
				userPkh,
				[]byte(cfg.Miner.Message),
			},
		)
		minerCredCbor, err := cbor.Encode(&minerCredential)
		if err != nil {
			panic(err)
		}
		// NOTE: we happen to use the same hash mechanism for our trie keys, so we
		// can reuse that hashing function here for convenience
		minerCredHash := storage.GetStorage().Trie().HashKey(minerCredCbor)
		// Create initial state from block data
		blockData := m.blockData.(models.TunaV2State)
		m.state = &TargetStateV2{
			Nonce:            randomNonce(),
			MinerCredHash:    minerCredHash,
			EpochTime:        blockData.EpochTime,
			BlockNumber:      blockData.BlockNumber,
			CurrentHash:      blockData.CurrentHash,
			LeadingZeros:     blockData.LeadingZeros,
			DifficultyNumber: blockData.DifficultyNumber,
		}
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
	var blockDataBlockNumber int64
	var difficultyNumber int64
	var leadingZeros int64
	if profileCfg.UseTunaV1 {
		blockData := m.blockData.(models.TunaV1State)
		epochTime = blockData.EpochTime + 90000 + realTimeNow - blockData.RealTimeNow
		blockDataBlockNumber = blockData.BlockNumber
		difficultyNumber = blockData.DifficultyNumber
		leadingZeros = blockData.LeadingZeros
	} else {
		blockData := m.blockData.(models.TunaV2State)
		epochTime = blockData.EpochTime + 90000 + realTimeNow - blockData.CurrentPosixTime
		blockDataBlockNumber = blockData.BlockNumber
		difficultyNumber = blockData.DifficultyNumber
		leadingZeros = blockData.LeadingZeros
	}

	// Adjust difficulty on epoch boundary
	epochNumber := DefaultEpochNumber
	if profileCfg.EpochNumber > 0 {
		epochNumber = profileCfg.EpochNumber
	}
	epochTarget := DefaultEpochTarget
	if profileCfg.EpochTarget > 0 {
		epochTarget = profileCfg.EpochTarget
	}
	if blockDataBlockNumber > 0 &&
		blockDataBlockNumber%int64(epochNumber) == 0 {
		adjustment := getDifficultyAdjustment(epochTime, int64(epochTarget))
		epochTime = 0
		newDifficulty := calculateDifficultyNumber(
			DifficultyMetrics{
				DifficultyNumber: difficultyNumber,
				LeadingZeros:     leadingZeros,
			},
			adjustment,
		)
		difficultyNumber = newDifficulty.DifficultyNumber
		leadingZeros = newDifficulty.LeadingZeros
	}

	// Construct the new block data
	var postDatum any
	if profileCfg.UseTunaV1 {
		blockData := m.blockData.(models.TunaV1State)
		difficulty := getDifficulty([]byte(targetHash))
		currentInterlink := calculateInterlink(
			targetHash,
			difficulty,
			m.getCurrentDifficulty(),
			blockData.Interlink,
		)
		postDatum = models.TunaV1State{
			BlockNumber:      blockData.BlockNumber + 1,
			CurrentHash:      targetHash,
			LeadingZeros:     leadingZeros,
			DifficultyNumber: difficultyNumber,
			EpochTime:        epochTime,
			RealTimeNow:      90000 + realTimeNow,
			Extra:            []byte(cfg.Miner.Message),
			Interlink:        currentInterlink,
		}
	} else {
		blockData := m.blockData.(models.TunaV2State)
		// Temporarily add new target hash to trie to calculate new block's merkle root hash
		trie := storage.GetStorage().Trie()
		trie.Lock()
		tmpHashKey := storage.HashValue(targetHash).Bytes()
		if err := trie.Update(tmpHashKey, targetHash, 0); err != nil {
			panic(fmt.Sprintf("failed to update storage for trie: %s", err))
		}
		postDatum = models.TunaV2State{
			BlockNumber:      blockData.BlockNumber + 1,
			CurrentHash:      targetHash,
			LeadingZeros:     leadingZeros,
			DifficultyNumber: difficultyNumber,
			EpochTime:        epochTime,
			CurrentPosixTime: 90000 + realTimeNow,
			MerkleRoot:       trie.Hash(),
		}
		// Remove item from trie until it comes in via the indexer
		_ = trie.Delete(tmpHashKey)
		trie.Unlock()
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

func (m *Miner) calculateHash() []byte {
	var tmpLeadingZeros int64
	var tmpDifficultyNumber int64
	switch v := m.blockData.(type) {
	case models.TunaV1State:
		tmpLeadingZeros = v.LeadingZeros
		tmpDifficultyNumber = v.DifficultyNumber
	case models.TunaV2State:
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
		stateBytes, err := m.state.MarshalCBOR()
		if err != nil {
			slog.Error(err.Error())
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

		// Increment hash counter
		m.hashCounter.Add(1)

		// Get the difficulty metrics for the hash
		metrics := getDifficulty(hash2)

		// Check the condition
		if metrics.LeadingZeros > tmpLeadingZeros ||
			(metrics.LeadingZeros == tmpLeadingZeros && metrics.DifficultyNumber < tmpDifficultyNumber) {
			return hash2
		}

		// Generate a new random nonce when nonceCount rolls over, and increment bytes in existing nonce otherwise
		if m.nonceCount == 0 {
			m.state.SetNonce(randomNonce())
		} else {
			nonce := m.state.GetNonce()
			// Increment each byte of the nonce
			for j := range 16 {
				nonce[j]++ //nolint:gosec
			}
			m.state.SetNonce(nonce)
		}
		m.nonceCount++
	}
}

func (m *Miner) getCurrentDifficulty() DifficultyMetrics {
	var tmpLeadingZeros int64
	var tmpDifficultyNumber int64
	switch v := m.blockData.(type) {
	case models.TunaV1State:
		tmpLeadingZeros = v.LeadingZeros
		tmpDifficultyNumber = v.DifficultyNumber
	case models.TunaV2State:
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
	interlink := currentInterlink

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

func getDifficultyAdjustment(
	totalEpochTime int64,
	epochTarget int64,
) DifficultyAdjustment {
	if epochTarget/totalEpochTime >= 4 && epochTarget%totalEpochTime > 0 {
		return DifficultyAdjustment{
			Numerator:   1,
			Denominator: 4,
		}
	} else if totalEpochTime/epochTarget >= 4 && totalEpochTime%epochTarget > 0 {
		return DifficultyAdjustment{
			Numerator:   4,
			Denominator: 1,
		}
	} else {
		return DifficultyAdjustment{
			Numerator:   totalEpochTime,
			Denominator: epochTarget,
		}
	}
}

func calculateDifficultyNumber(
	diffMetrics DifficultyMetrics,
	diffAdjustment DifficultyAdjustment,
) DifficultyMetrics {
	newPaddedDifficulty := (diffMetrics.DifficultyNumber * 16 * diffAdjustment.Numerator) / diffAdjustment.Denominator
	newDifficulty := newPaddedDifficulty / 16
	if newPaddedDifficulty/65536 == 0 {
		if diffMetrics.LeadingZeros >= 62 {
			return DifficultyMetrics{
				DifficultyNumber: 4096,
				LeadingZeros:     62,
			}
		} else {
			return DifficultyMetrics{
				DifficultyNumber: newPaddedDifficulty,
				LeadingZeros:     diffMetrics.LeadingZeros + 1,
			}
		}
	} else if newDifficulty/65536 > 0 {
		if diffMetrics.LeadingZeros <= 2 {
			return DifficultyMetrics{
				DifficultyNumber: 65535,
				LeadingZeros:     2,
			}
		} else {
			return DifficultyMetrics{
				DifficultyNumber: newDifficulty / 16,
				LeadingZeros:     diffMetrics.LeadingZeros - 1,
			}
		}
	} else {
		return DifficultyMetrics{
			DifficultyNumber: newDifficulty,
			LeadingZeros:     diffMetrics.LeadingZeros,
		}
	}
}
