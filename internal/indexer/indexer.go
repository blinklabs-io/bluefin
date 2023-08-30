package indexer

import (
	"encoding/hex"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
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
	pipeline *pipeline.Pipeline
	datum    []byte
}

type Datum struct {
	nonce uint64
	state State
}

type State struct {
	BlockNumber      uint64
	CurrentHash      []byte
	LeadingZeros     uint64
	DifficultyNumber uint64
	EpochTime        uint64
}

// Singleton indexer instance
var globalIndexer = &Indexer{}

func (i *Indexer) Start() error {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithStatusUpdateFunc(func(status input_chainsync.ChainSyncStatus) {
			if err := storage.GetStorage().UpdateCursor(status.SlotNumber, status.BlockHash); err != nil {
				logger.Errorf("failed to update cursor: %s", err)
			}
		}),
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
	cursorSlotNumber, cursorBlockHash, err := storage.GetStorage().GetCursor()
	if err != nil {
		return err
	}
	if cursorSlotNumber > 0 {
		logger.Infof("found previous chainsync cursor: %d, %s", cursorSlotNumber, cursorBlockHash)
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
		filter_chainsync.WithAddresses([]string{cfg.Indexer.ScriptAddress, bursa.PaymentAddress}),
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
	logger := logging.GetLogger()
	eventTx := evt.Payload.(input_chainsync.TransactionEvent)
	for _, txOutput := range eventTx.Outputs {
		datum := txOutput.Datum()
		if datum != nil {
			if _, err := datum.Decode(); err != nil {
				logger.Warnf("error decoding TX (%s) output datum: %s", eventTx.TransactionHash, err)
				return err
			}
			datumFields := datum.Value().(cbor.Constructor).Fields()
			var data = Datum{
				nonce: datumFields[0].(uint64),
			}
			state := datumFields[1].(cbor.ByteString).String()
			// TODO: do the thing

			logger.Infof("found updated datum: nonce: %d, state: %s", data.nonce, state)
		}
	}
	return nil
}

// GetIndexer returns the global indexer instance
func GetIndexer() *Indexer {
	return globalIndexer
}
