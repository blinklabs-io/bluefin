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

package storage

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
	minerBlockDataKey  = "miner_block_data"
)

type Storage struct {
	db *badger.DB
}

var globalStorage = &Storage{}

func (s *Storage) Load() error {
	cfg := config.GetConfig()
	badgerOpts := badger.DefaultOptions(cfg.Storage.Directory).
		WithLogger(NewBadgerLogger()).
		// The default INFO logging is a bit verbose
		WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(badgerOpts)
	// TODO: setup automatic GC for Badger
	if err != nil {
		return err
	}
	s.db = db
	//defer db.Close()
	return nil
}

func (s *Storage) UpdateCursor(slotNumber uint64, blockHash string) error {
	err := s.db.Update(func(txn *badger.Txn) error {
		val := fmt.Sprintf("%d,%s", slotNumber, blockHash)
		if err := txn.Set([]byte(chainsyncCursorKey), []byte(val)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *Storage) GetCursor() (uint64, string, error) {
	var slotNumber uint64
	var blockHash string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(chainsyncCursorKey))
		if err != nil {
			return err
		}
		err = item.Value(func(v []byte) error {
			var err error
			cursorParts := strings.Split(string(v), ",")
			slotNumber, err = strconv.ParseUint(cursorParts[0], 10, 64)
			if err != nil {
				return err
			}
			blockHash = cursorParts[1]
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err == badger.ErrKeyNotFound {
		return 0, "", nil
	}
	return slotNumber, blockHash, err
}

func (s *Storage) UpdateBlockData(blockData any) error {
	blockDataCbor, err := cbor.Encode(blockData)
	if err != nil {
		return err
	}
	err = s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set([]byte(minerBlockDataKey), blockDataCbor); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *Storage) GetBlockData(dest any) error {
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(minerBlockDataKey))
		if err != nil {
			return err
		}
		err = item.Value(func(v []byte) error {
			if _, err := cbor.Decode(v, dest); err != nil {
				return err
			}
			return nil
		})
		return err
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	}
	return nil
}

func (s *Storage) AddUtxo(
	address string,
	txId string,
	txOutIdx uint32,
	txOutBytes []byte,
) error {
	key := fmt.Sprintf("utxo_%s_%s.%d", address, txId, txOutIdx)
	err := s.db.Update(func(txn *badger.Txn) error {
		// Wrap TX output in UTxO structure to make it easier to consume later
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			return err
		}
		// Create temp UTxO structure
		utxoTmp := []any{
			// Transaction output reference
			[]any{
				txIdBytes,
				uint32(txOutIdx),
			},
			// Transaction output CBOR
			cbor.RawMessage(txOutBytes),
		}
		// Convert to CBOR
		cborBytes, err := cbor.Encode(&utxoTmp)
		if err != nil {
			return err
		}
		if err := txn.Set([]byte(key), cborBytes); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *Storage) RemoveUtxo(
	address string,
	txId string,
	utxoIdx uint32,
) error {
	key := fmt.Sprintf("utxo_%s_%s.%d", address, txId, utxoIdx)
	err := s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Delete([]byte(key)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	}
	return nil
}

func (s *Storage) GetUtxos(address string) ([][]byte, error) {
	var ret [][]byte
	keyPrefix := []byte(fmt.Sprintf("utxo_%s_", address))
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				// Create copy of value for use outside of transaction
				valCopy := append([]byte{}, v...)
				ret = append(ret, valCopy)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, nil
	}
	return ret, nil
}

func GetStorage() *Storage {
	return globalStorage
}

// BadgerLogger is a wrapper type to give our logger the expected interface
type BadgerLogger struct {
	*logging.Logger
}

func NewBadgerLogger() *BadgerLogger {
	return &BadgerLogger{
		Logger: logging.GetLogger(),
	}
}

func (b *BadgerLogger) Warningf(msg string, args ...any) {
	b.Logger.Warnf(msg, args...)
}
