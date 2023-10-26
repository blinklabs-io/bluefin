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

package indexer

import (
	"encoding/hex"

	"github.com/blinklabs-io/bluefin/internal/common"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/miner"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"

	"github.com/blinklabs-io/gouroboros/cbor"
	ocommon "github.com/blinklabs-io/gouroboros/protocol/common"
	"github.com/blinklabs-io/snek/event"
	filter_chainsync "github.com/blinklabs-io/snek/filter/chainsync"
	filter_event "github.com/blinklabs-io/snek/filter/event"
	input_chainsync "github.com/blinklabs-io/snek/input/chainsync"
	output_embedded "github.com/blinklabs-io/snek/output/embedded"
	"github.com/blinklabs-io/snek/pipeline"
)

type Indexer struct {
	pipeline      *pipeline.Pipeline
	cursorSlot    uint64
	cursorHash    string
	tipSlot       uint64
	tipHash       string
	tipReached    bool
	lastBlockData common.BlockData
}

// Singleton indexer instance
var globalIndexer = &Indexer{}

func (i *Indexer) Start() error {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()
	// Load saved block data
	if err := storage.GetStorage().GetBlockData(&(i.lastBlockData)); err != nil {
		return err
	}
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithBulkMode(true),
		input_chainsync.WithStatusUpdateFunc(i.updateStatus),
	}
	if cfg.Indexer.NetworkMagic > 0 {
		inputOpts = append(
			inputOpts,
			input_chainsync.WithNetworkMagic(cfg.Indexer.NetworkMagic),
		)
	} else {
		inputOpts = append(
			inputOpts,
			input_chainsync.WithNetwork(cfg.Indexer.Network),
		)
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
		filter_event.WithTypes([]string{"chainsync.transaction"}),
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
	return nil
}

func (i *Indexer) handleEvent(evt event.Event) error {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	eventTx := evt.Payload.(input_chainsync.TransactionEvent)
	eventCtx := evt.Context.(input_chainsync.TransactionContext)
	// Delete used UTXOs
	for _, txInput := range eventTx.Inputs {
		// We don't have a ledger DB to know where the TX inputs came from, so we just try deleting them for our known addresses
		for _, tmpAddress := range []string{cfg.Indexer.ScriptAddress, wallet.GetWallet().PaymentAddress} {
			if err := storage.GetStorage().RemoveUtxo(tmpAddress, txInput.Id().String(), txInput.Index()); err != nil {
				return err
			}
		}
	}
	for idx, txOutput := range eventTx.Outputs {
		// Write UTXO to storage
		if err := storage.GetStorage().AddUtxo(
			txOutput.Address().String(),
			eventCtx.TransactionHash,
			uint32(idx),
			txOutput.Cbor(),
		); err != nil {
			return err
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
				datumFields := datum.Value().(cbor.Constructor).Fields()
				blockData := common.BlockData{
					BlockNumber:      int64(datumFields[0].(uint64)),
					TargetHash:       datumFields[1].(cbor.ByteString).Bytes(),
					LeadingZeros:     int64(datumFields[2].(uint64)),
					DifficultyNumber: int64(datumFields[3].(uint64)),
					EpochTime:        int64(datumFields[4].(uint64)),
					RealTimeNow:      int64(datumFields[5].(uint64)),
				}
				// Some blocks have the int 0 in this field, so we protect against it
				switch v := datumFields[6].(type) {
				case cbor.ByteString:
					blockData.Message = v.Bytes()
				}
				// Copy interlink
				interlink := [][]byte{}
				for _, data := range datumFields[7].([]any) {
					interlink = append(
						interlink,
						data.(cbor.ByteString).Bytes(),
					)
				}
				blockData.Interlink = interlink[:]
				i.lastBlockData = blockData
				if err := storage.GetStorage().UpdateBlockData(&(i.lastBlockData)); err != nil {
					return err
				}

				logger.Infof(
					"found updated datum: block number: %d, hash: %x, leading zeros: %d, difficulty number: %d, epoch time: %d, real time now: %d, message: %s",
					blockData.BlockNumber,
					blockData.TargetHash,
					blockData.LeadingZeros,
					blockData.DifficultyNumber,
					blockData.EpochTime,
					blockData.RealTimeNow,
					string(blockData.Message),
				)

				// Restart miners for new datum
				if i.tipReached {
					miner.GetManager().Stop()
					miner.GetManager().Start(i.lastBlockData)
				}
			}
		}
	}
	return nil
}

func (i *Indexer) updateStatus(status input_chainsync.ChainSyncStatus) {
	logger := logging.GetLogger()
	// Check if we've hit chain tip
	if !i.tipReached && status.TipReached {
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
