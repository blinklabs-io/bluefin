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

package indexer

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/miner"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"

	"github.com/blinklabs-io/adder/event"
	filter_chainsync "github.com/blinklabs-io/adder/filter/chainsync"
	filter_event "github.com/blinklabs-io/adder/filter/event"
	input_chainsync "github.com/blinklabs-io/adder/input/chainsync"
	output_embedded "github.com/blinklabs-io/adder/output/embedded"
	"github.com/blinklabs-io/adder/pipeline"
	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	ocommon "github.com/blinklabs-io/gouroboros/protocol/common"
)

const (
	syncStatusLogInterval = 30 * time.Second
	rollbackSlots         = 50 * 20 // 50 blocks with a 20s average between
)

type Indexer struct {
	pipeline      *pipeline.Pipeline
	cursorSlot    uint64
	cursorHash    string
	tipSlot       uint64
	tipHash       string
	tipReached    bool
	syncLogTimer  *time.Timer
	lastBlockData any
}

// Singleton indexer instance
var globalIndexer = &Indexer{}

func (i *Indexer) Start() error {
	cfg := config.GetConfig()
	profileCfg := config.GetProfile()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()
	// Load saved block data
	var lastBlockDataBytes cbor.RawMessage
	if err := storage.GetStorage().GetBlockData(&(lastBlockDataBytes)); err != nil {
		return err
	}
	if profileCfg.UseTunaV1 {
		var tmpBlockData models.TunaV1State
		if len(lastBlockDataBytes) > 0 {
			if _, err := cbor.Decode(lastBlockDataBytes, &tmpBlockData); err != nil {
				return fmt.Errorf("failed to parse last block data: %s", err)
			}
		}
		i.lastBlockData = tmpBlockData
	} else {
		var tmpBlockData models.TunaV2State
		if len(lastBlockDataBytes) > 0 {
			if _, err := cbor.Decode(lastBlockDataBytes, &tmpBlockData); err != nil {
				return fmt.Errorf("failed to parse last block data: %s", err)
			}
		}
		i.lastBlockData = tmpBlockData
	}
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithBulkMode(true),
		input_chainsync.WithAutoReconnect(true),
		input_chainsync.WithLogger(logger),
		input_chainsync.WithStatusUpdateFunc(i.updateStatus),
		input_chainsync.WithNetwork(cfg.Network),
	}
	if cfg.Indexer.Address != "" {
		inputOpts = append(
			inputOpts,
			input_chainsync.WithAddress(cfg.Indexer.Address),
		)
	}
	cursorSlotNumber, cursorBlockHash, err := storage.GetStorage().GetCursor()
	if err != nil {
		return err
	}
	if cursorSlotNumber > 0 {
		logger.Infof(
			"found previous chainsync cursor: %d, %s",
			cursorSlotNumber,
			cursorBlockHash,
		)
		hashBytes, err := hex.DecodeString(cursorBlockHash)
		if err != nil {
			return err
		}
		inputOpts = append(
			inputOpts,
			input_chainsync.WithIntersectPoints(
				[]ocommon.Point{
					{
						Hash: hashBytes,
						Slot: cursorSlotNumber,
					},
				},
			),
		)
	} else if cfg.Indexer.InterceptHash != "" && cfg.Indexer.InterceptSlot > 0 {
		hashBytes, err := hex.DecodeString(cfg.Indexer.InterceptHash)
		if err != nil {
			return err
		}
		inputOpts = append(
			inputOpts,
			input_chainsync.WithIntersectPoints(
				[]ocommon.Point{
					{
						Hash: hashBytes,
						Slot: cfg.Indexer.InterceptSlot,
					},
				},
			),
		)
	}
	input := input_chainsync.New(
		inputOpts...,
	)
	i.pipeline.AddInput(input)
	// Configure pipeline filters
	// We only care about transaction events
	filterEvent := filter_event.New(
		filter_event.WithTypes([]string{"chainsync.transaction", "chainsync.rollback"}),
	)
	i.pipeline.AddFilter(filterEvent)
	// We only care about transactions on a certain address
	filterChainsync := filter_chainsync.New(
		filter_chainsync.WithAddresses(
			[]string{cfg.Indexer.ScriptAddress, bursa.PaymentAddress},
		),
	)
	i.pipeline.AddFilter(filterChainsync)
	// Configure pipeline output
	output := output_embedded.New(
		output_embedded.WithCallbackFunc(i.handleEvent),
	)
	i.pipeline.AddOutput(output)
	// Start pipeline
	if err := i.pipeline.Start(); err != nil {
		logger.Fatalf("failed to start pipeline: %s\n", err)
	}
	// Start error handler
	go func() {
		err, ok := <-i.pipeline.ErrorChan()
		if ok {
			logger.Fatalf("pipeline failed: %s\n", err)
		}
	}()
	// Schedule periodic catch-up sync log messages
	i.scheduleSyncStatusLog()
	return nil
}

func (i *Indexer) handleEvent(evt event.Event) error {
	switch evt.Payload.(type) {
	case input_chainsync.RollbackEvent:
		return i.handleEventRollback(evt)
	case input_chainsync.TransactionEvent:
		return i.handleEventTransaction(evt)
	default:
		return fmt.Errorf("unknown event payload type: %T", evt.Payload)
	}
}

func (i *Indexer) handleEventRollback(evt event.Event) error {
	logger := logging.GetLogger()
	store := storage.GetStorage()
	eventRollback := evt.Payload.(input_chainsync.RollbackEvent)
	store.Lock()
	defer store.Unlock()
	if err := store.Rollback(eventRollback.SlotNumber); err != nil {
		return err
	}
	logger.Info(
		fmt.Sprintf("rolled back to %d.%s", eventRollback.SlotNumber, eventRollback.BlockHash),
	)
	// Purge older deleted UTxOs
	if err := store.PurgeDeletedUtxos(eventRollback.SlotNumber - rollbackSlots); err != nil {
		logger.Warn(
			fmt.Sprintf("failed to purge deleted UTxOs: %s", err),
		)
	}
	return nil
}

func (i *Indexer) handleEventTransaction(evt event.Event) error {
	cfg := config.GetConfig()
	profileCfg := config.GetProfile()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()
	store := storage.GetStorage()
	eventTx := evt.Payload.(input_chainsync.TransactionEvent)
	eventCtx := evt.Context.(input_chainsync.TransactionContext)
	store.Lock()
	defer store.Unlock()
	// Delete used UTXOs
	for _, txInput := range eventTx.Transaction.Consumed() {
		// We don't have a ledger DB to know where the TX inputs came from, so we just try deleting them for our known addresses
		for _, tmpAddress := range []string{cfg.Indexer.ScriptAddress, bursa.PaymentAddress} {
			if err := store.RemoveUtxo(tmpAddress, txInput.Id().String(), txInput.Index(), eventCtx.SlotNumber); err != nil {
				return err
			}
		}
	}
	for idx, txOutput := range eventTx.Transaction.Produced() {
		if txOutput.Address().String() == cfg.Indexer.ScriptAddress ||
			txOutput.Address().String() == bursa.PaymentAddress {
			// Write UTXO to storage
			if err := store.AddUtxo(
				txOutput.Address().String(),
				eventCtx.TransactionHash,
				uint32(idx),
				txOutput.Cbor(),
				eventCtx.SlotNumber,
			); err != nil {
				return err
			}
		}
		// Handle datum for script address
		if txOutput.Address().String() == cfg.Indexer.ScriptAddress {
			datum := txOutput.Datum()
			if datum != nil {
				if _, err := datum.Decode(); err != nil {
					logger.Warnf(
						"error decoding TX (%s) output datum: %s",
						eventCtx.TransactionHash,
						err,
					)
					return err
				}
				if profileCfg.UseTunaV1 {
					var blockData models.TunaV1State
					if _, err := cbor.Decode(datum.Cbor(), &blockData); err != nil {
						logger.Warnf(
							"error decoding TX (%s) output datum: %s",
							eventCtx.TransactionHash,
							err,
						)
						return err
					}
					i.lastBlockData = blockData
					var tmpExtra any
					switch v := blockData.Extra.(type) {
					case []byte:
						tmpExtra = string(v)
					default:
						tmpExtra = v
					}
					logger.Infof(
						"found updated datum: block number: %d, hash: %x, leading zeros: %d, difficulty number: %d, epoch time: %d, real time now: %d, extra: %v",
						blockData.BlockNumber,
						blockData.CurrentHash,
						blockData.LeadingZeros,
						blockData.DifficultyNumber,
						blockData.EpochTime,
						blockData.RealTimeNow,
						tmpExtra,
					)
				} else {
					var blockData models.TunaV2State
					if _, err := cbor.Decode(datum.Cbor(), &blockData); err != nil {
						logger.Warnf(
							"error decoding TX (%s) output datum: %s",
							eventCtx.TransactionHash,
							err,
						)
						return err
					}
					i.lastBlockData = blockData
					// Update trie
					trie := store.Trie()
					trie.Lock()
					trieKey := trie.HashKey(blockData.CurrentHash)
					if err := trie.Update(trieKey, blockData.CurrentHash, eventCtx.SlotNumber); err != nil {
						trie.Unlock()
						return err
					}
					trie.Unlock()
					logger.Infof(
						"found updated datum: block number: %d, hash: %x, leading zeros: %d, difficulty number: %d, epoch time: %d, current POSIX time: %d, merkle root = %x",
						blockData.BlockNumber,
						blockData.CurrentHash,
						blockData.LeadingZeros,
						blockData.DifficultyNumber,
						blockData.EpochTime,
						blockData.CurrentPosixTime,
						blockData.MerkleRoot,
					)
				}

				if err := store.UpdateBlockData(&(i.lastBlockData)); err != nil {
					return err
				}

				if i.tipReached {
					// TODO: defer starting miner until after processing all TX outputs
					// Restart miners for new datum
					miner.GetManager().Stop()
					miner.GetManager().Start(i.lastBlockData)
				}
			}
		}
	}
	// Purge older deleted UTxOs
	if i.tipReached {
		if err := store.PurgeDeletedUtxos(eventCtx.SlotNumber - rollbackSlots); err != nil {
			logger.Warn(
				fmt.Sprintf("failed to purge deleted UTxOs: %s", err),
			)
		}
	}
	return nil
}

func (i *Indexer) scheduleSyncStatusLog() {
	i.syncLogTimer = time.AfterFunc(syncStatusLogInterval, i.syncStatusLog)
}

func (i *Indexer) syncStatusLog() {
	logger := logging.GetLogger()
	logger.Infof(
		"catch-up sync in progress: at %d.%s (current tip slot is %d)",
		i.cursorSlot,
		i.cursorHash,
		i.tipSlot,
	)
	i.scheduleSyncStatusLog()
}

func (i *Indexer) updateStatus(status input_chainsync.ChainSyncStatus) {
	logger := logging.GetLogger()
	// Check if we've hit chain tip
	if !i.tipReached && status.TipReached {
		if i.syncLogTimer != nil {
			i.syncLogTimer.Stop()
		}
		i.tipReached = true
		miner.GetManager().Start(i.lastBlockData)
	}
	i.cursorSlot = status.SlotNumber
	i.cursorHash = status.BlockHash
	i.tipSlot = status.TipSlotNumber
	i.tipHash = status.TipBlockHash
	if err := storage.GetStorage().UpdateCursor(status.SlotNumber, status.BlockHash); err != nil {
		logger.Errorf("failed to update cursor: %s", err)
	}
}

// GetIndexer returns the global indexer instance
func GetIndexer() *Indexer {
	return globalIndexer
}
