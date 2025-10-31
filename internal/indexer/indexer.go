// Copyright 2025 Blink Labs Software
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
	"log/slog"
	"os"
	"time"

	"github.com/blinklabs-io/adder/event"
	filter_event "github.com/blinklabs-io/adder/filter/event"
	input_chainsync "github.com/blinklabs-io/adder/input/chainsync"
	output_embedded "github.com/blinklabs-io/adder/output/embedded"
	"github.com/blinklabs-io/adder/pipeline"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/miner"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
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
	// Load saved block data
	var lastBlockDataBytes cbor.RawMessage
	if err := storage.GetStorage().GetBlockData(&(lastBlockDataBytes)); err != nil {
		return err
	}
	if profileCfg.UseTunaV1 {
		var tmpBlockData models.TunaV1State
		if len(lastBlockDataBytes) > 0 {
			if _, err := cbor.Decode(lastBlockDataBytes, &tmpBlockData); err != nil {
				return fmt.Errorf("failed to parse last block data: %w", err)
			}
		}
		i.lastBlockData = tmpBlockData
	} else {
		var tmpBlockData models.TunaV2State
		if len(lastBlockDataBytes) > 0 {
			if _, err := cbor.Decode(lastBlockDataBytes, &tmpBlockData); err != nil {
				return fmt.Errorf("failed to parse last block data: %w", err)
			}
		}
		i.lastBlockData = tmpBlockData
	}
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithAutoReconnect(true),
		input_chainsync.WithLogger(logging.GetLogger()),
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
		slog.Info(
			fmt.Sprintf(
				"found previous chainsync cursor: %d, %s",
				cursorSlotNumber,
				cursorBlockHash,
			),
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
		filter_event.WithTypes(
			[]string{"chainsync.transaction", "chainsync.rollback"},
		),
	)
	i.pipeline.AddFilter(filterEvent)
	// Configure pipeline output
	output := output_embedded.New(
		output_embedded.WithCallbackFunc(i.handleEvent),
	)
	i.pipeline.AddOutput(output)
	// Start pipeline
	if err := i.pipeline.Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start pipeline: %s\n", err),
		)
		os.Exit(1)
	}
	// Start error handler
	go func() {
		err, ok := <-i.pipeline.ErrorChan()
		if ok {
			slog.Error(
				fmt.Sprintf("pipeline failed: %s\n", err),
			)
			os.Exit(1)
		}
	}()
	// Schedule periodic catch-up sync log messages
	i.scheduleSyncStatusLog()
	return nil
}

func (i *Indexer) handleEvent(evt event.Event) error {
	switch evt.Payload.(type) {
	case event.RollbackEvent:
		return i.handleEventRollback(evt)
	case event.TransactionEvent:
		return i.handleEventTransaction(evt)
	default:
		return fmt.Errorf("unknown event payload type: %T", evt.Payload)
	}
}

func (i *Indexer) handleEventRollback(evt event.Event) error {
	store := storage.GetStorage()
	eventRollback := evt.Payload.(event.RollbackEvent)
	store.Lock()
	defer store.Unlock()
	if err := store.Rollback(eventRollback.SlotNumber); err != nil {
		return err
	}
	slog.Info(
		fmt.Sprintf(
			"rolled back to %d.%s",
			eventRollback.SlotNumber,
			eventRollback.BlockHash,
		),
	)
	// Purge older deleted UTxOs
	if err := store.PurgeDeletedUtxos(eventRollback.SlotNumber - rollbackSlots); err != nil {
		slog.Warn(
			fmt.Sprintf("failed to purge deleted UTxOs: %s", err),
		)
	}
	return nil
}

func (i *Indexer) handleEventTransaction(evt event.Event) error {
	cfg := config.GetConfig()
	profileCfg := config.GetProfile()
	bursa := wallet.GetWallet()
	store := storage.GetStorage()
	eventTx := evt.Payload.(event.TransactionEvent)
	eventCtx := evt.Context.(event.TransactionContext)
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
	// Check for TUNA mints
	var tunaMintCount int64
	var tunaPolicyId string
	if profileCfg.UseTunaV1 {
		tunaPolicyId = profileCfg.ValidatorHash
	} else {
		tunaPolicyId = profileCfg.MintValidatorHash
	}
	tunaPolicyIdHex, err := hex.DecodeString(tunaPolicyId)
	if err != nil {
		return err
	}
	mints := eventTx.Transaction.AssetMint()
	if mints != nil {
		tunaMintCount = mints.Asset(
			ledger.Blake2b224(tunaPolicyIdHex),
			[]byte("TUNA"),
		)
	}
	// Process produced UTxOs
	startMiner := false
	for _, utxo := range eventTx.Transaction.Produced() {
		// Check for reference inputs
		for _, refInput := range profileCfg.ScriptRefInputs {
			if refInput.TxId == eventCtx.TransactionHash &&
				refInput.OutputIdx == utxo.Id.Index() {
				// Record script ref UTxO
				if err := store.AddUtxo(
					"script_ref",
					eventCtx.TransactionHash,
					utxo.Id.Index(),
					utxo.Output.Cbor(),
					eventCtx.SlotNumber,
				); err != nil {
					return err
				}
			}
		}
		outputAddress := utxo.Output.Address().String()
		// Ignore outputs to addresses that we don't care about
		if outputAddress != cfg.Indexer.ScriptAddress &&
			outputAddress != bursa.PaymentAddress {
			continue
		}
		// Write UTXO to storage
		if err := store.AddUtxo(
			outputAddress,
			eventCtx.TransactionHash,
			utxo.Id.Index(),
			utxo.Output.Cbor(),
			eventCtx.SlotNumber,
		); err != nil {
			return err
		}
		// Show message when receiving freshly minted TUNA
		if outputAddress == bursa.PaymentAddress {
			if tunaMintCount > 0 {
				if utxo.Output.Assets() != nil {
					outputTunaCount := utxo.Output.Assets().Asset(
						ledger.Blake2b224(tunaPolicyIdHex),
						[]byte("TUNA"),
					)
					if outputTunaCount > 0 {
						slog.Info(
							fmt.Sprintf("minted %d TUNA!", tunaMintCount),
						)
					}
				}
			}
		}
		// Handle datum for script address
		if outputAddress == cfg.Indexer.ScriptAddress {
			datum := utxo.Output.Datum()
			if datum != nil {
				if profileCfg.UseTunaV1 {
					var blockData models.TunaV1State
					if _, err := cbor.Decode(datum.Cbor(), &blockData); err != nil {
						slog.Warn(
							fmt.Sprintf(
								"error decoding TX (%s) output datum: %s",
								eventCtx.TransactionHash,
								err,
							),
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
					slog.Info(
						fmt.Sprintf(
							"found updated datum: block number: %d, hash: %x, leading zeros: %d, difficulty number: %d, epoch time: %d, real time now: %d, extra: %v",
							blockData.BlockNumber,
							blockData.CurrentHash,
							blockData.LeadingZeros,
							blockData.DifficultyNumber,
							blockData.EpochTime,
							blockData.RealTimeNow,
							tmpExtra,
						),
					)
				} else {
					var blockData models.TunaV2State
					if _, err := cbor.Decode(datum.Cbor(), &blockData); err != nil {
						slog.Warn(
							fmt.Sprintf(
								"error decoding TX (%s) output datum: %s",
								eventCtx.TransactionHash,
								err,
							),
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
					slog.Info(
						fmt.Sprintf(
							"found updated datum: block number: %d, hash: %x, leading zeros: %d, difficulty number: %d, epoch time: %d, current POSIX time: %d, merkle root = %x",
							blockData.BlockNumber,
							blockData.CurrentHash,
							blockData.LeadingZeros,
							blockData.DifficultyNumber,
							blockData.EpochTime,
							blockData.CurrentPosixTime,
							blockData.MerkleRoot,
						),
					)
				}

				if err := store.UpdateBlockData(&(i.lastBlockData)); err != nil {
					return err
				}

				if i.tipReached {
					startMiner = true
				}
			}
		}
	}
	// Purge older deleted UTxOs
	if i.tipReached {
		if err := store.PurgeDeletedUtxos(eventCtx.SlotNumber - rollbackSlots); err != nil {
			slog.Warn(
				fmt.Sprintf("failed to purge deleted UTxOs: %s", err),
			)
		}
	}
	// (Re)start miner if we got a new datum
	if startMiner {
		miner.GetManager().Stop()
		miner.GetManager().Start(i.lastBlockData)
	}
	return nil
}

func (i *Indexer) scheduleSyncStatusLog() {
	i.syncLogTimer = time.AfterFunc(syncStatusLogInterval, i.syncStatusLog)
}

func (i *Indexer) syncStatusLog() {
	slog.Info(
		fmt.Sprintf(
			"catch-up sync in progress: at %d.%s (current tip slot is %d)",
			i.cursorSlot,
			i.cursorHash,
			i.tipSlot,
		),
	)
	i.scheduleSyncStatusLog()
}

func (i *Indexer) updateStatus(status input_chainsync.ChainSyncStatus) {
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
		slog.Error(
			fmt.Sprintf("failed to update cursor: %s", err),
		)
	}
}

// GetIndexer returns the global indexer instance
func GetIndexer() *Indexer {
	return globalIndexer
}
