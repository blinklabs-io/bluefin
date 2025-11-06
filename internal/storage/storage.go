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

package storage

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
	fingerprintKey     = "config_fingerprint"
	minerBlockDataKey  = "miner_block_data"
)

type Storage struct {
	db   *badger.DB
	trie *Trie
	sync.Mutex
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
	// defer db.Close()
	if err := s.compareFingerprint(); err != nil {
		return err
	}
	// Populate trie
	trie, err := NewTrie(s.db, cfg.Profile)
	if err != nil {
		return err
	}
	s.trie = trie
	return nil
}

func (s *Storage) compareFingerprint() error {
	cfg := config.GetConfig()
	fingerprint := fmt.Sprintf(
		"network=%s,profile=%s",
		cfg.Network,
		cfg.Profile,
	)
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(fingerprintKey))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				if err := txn.Set([]byte(fingerprintKey), []byte(fingerprint)); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}
		err = item.Value(func(v []byte) error {
			if string(v) != fingerprint {
				return fmt.Errorf(
					"config fingerprint in DB doesn't match current config: %s",
					v,
				)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) Trie() *Trie {
	return s.trie
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
	if errors.Is(err, badger.ErrKeyNotFound) {
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
		if errors.Is(err, badger.ErrKeyNotFound) {
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
	slot uint64,
) error {
	if slot > math.MaxInt {
		return errors.New("slot number int overflow")
	}
	keyUtxo := fmt.Sprintf("utxo_%s_%s.%d", address, txId, txOutIdx)
	keyAdded := keyUtxo + `_added`
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
		if err := txn.Set([]byte(keyUtxo), cborBytes); err != nil {
			return err
		}
		// Set "added" key to provided slot number
		if err := txn.Set(
			[]byte(keyAdded),
			[]byte(
				// Convert slot to string for storage
				strconv.Itoa(int(slot)), // #nosec G115
			),
		); err != nil {
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
	slot uint64,
) error {
	if slot > math.MaxInt {
		return errors.New("slot number int overflow")
	}
	keyUtxo := fmt.Sprintf("utxo_%s_%s.%d", address, txId, utxoIdx)
	keyDeleted := keyUtxo + `_deleted`
	err := s.db.Update(func(txn *badger.Txn) error {
		// Check if UTxO exists at all
		if _, err := txn.Get([]byte(keyUtxo)); err != nil {
			return err
		}
		// Set "deleted" key to provided slot number
		if err := txn.Set(
			[]byte(keyDeleted),
			[]byte(
				// Convert slot to string for storage
				strconv.Itoa(int(slot)), // #nosec G115
			),
		); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Storage) GetScriptRefUtxo(txId string, outputIdx int) ([]byte, error) {
	var ret []byte
	key := fmt.Appendf(nil, "utxo_script_ref_%s.%d", txId, outputIdx)
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		ret, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *Storage) GetUtxos(address string) ([][]byte, error) {
	var ret [][]byte
	keyPrefix := fmt.Appendf(nil, "utxo_%s_", address)
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			key := item.Key()
			// Ignore "added" and "deleted" metadata keys when iterating
			if strings.HasSuffix(string(key), `_deleted`) ||
				strings.HasSuffix(string(key), `_added`) {
				continue
			}
			// Ignore "deleted" UTxOs
			keyDeleted := string(key) + `_deleted`
			if _, err := txn.Get([]byte(keyDeleted)); !errors.Is(
				err,
				badger.ErrKeyNotFound,
			) {
				continue
			}
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			ret = append(ret, val)
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

func (s *Storage) Rollback(slot uint64) error {
	keyPrefix := []byte(`utxo_`)
	var deleteKeys [][]byte
	err := s.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			// Ignore "added" and "deleted" metadata keys when iterating
			if strings.HasSuffix(string(key), `_deleted`) ||
				strings.HasSuffix(string(key), `_added`) {
				continue
			}
			// Restore UTxOs deleted after rollback slot
			keyDeleted := string(key) + `_deleted`
			delItem, err := txn.Get([]byte(keyDeleted))
			if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
			if !errors.Is(err, badger.ErrKeyNotFound) {
				delVal, err := delItem.ValueCopy(nil)
				if err != nil {
					return err
				}
				delSlot, err := strconv.ParseUint(string(delVal), 10, 64)
				if err != nil {
					return err
				}
				if delSlot > slot {
					slog.Debug(
						fmt.Sprintf(
							"deleting key %s ('deleted' slot %d) to restore deleted UTxO",
							keyDeleted,
							delSlot,
						),
					)
					deleteKeys = append(deleteKeys, []byte(keyDeleted))
				}
			}
			// Remove UTxOs added after rollback slot
			keyAdded := string(key) + `_added`
			addItem, err := txn.Get([]byte(keyAdded))
			if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
			if !errors.Is(err, badger.ErrKeyNotFound) {
				addVal, err := addItem.ValueCopy(nil)
				if err != nil {
					return err
				}
				addSlot, err := strconv.ParseUint(string(addVal), 10, 64)
				if err != nil {
					return err
				}
				if addSlot > slot {
					slog.Debug(
						fmt.Sprintf(
							"deleting keys %s ('added' slot %d) and %s to remove rolled-back UTxO",
							key,
							addSlot,
							keyAdded,
						),
					)
					deleteKeys = append(
						deleteKeys,
						key,
						[]byte(keyAdded),
					)
				}
			}
		}
		// We delete the keys outside of the iterator, because apparently you can't delete
		// the current key when iterating
		for _, key := range deleteKeys {
			if err := txn.Delete([]byte(key)); err != nil {
				return err
			}
		}
		return nil
	})
	// Remove rolled-back hashes from trie
	if err := s.trie.Rollback(slot); err != nil {
		return err
	}
	return err
}

func (s *Storage) PurgeDeletedUtxos(beforeSlot uint64) error {
	keyPrefix := []byte(`utxo_`)
	var deleteKeys [][]byte
	err := s.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			// Ignore "added" and "deleted" metadata keys when iterating
			if strings.HasSuffix(string(key), `_deleted`) ||
				strings.HasSuffix(string(key), `_added`) {
				continue
			}
			// Check for "deleted" key
			keyDeleted := string(key) + `_deleted`
			delItem, err := txn.Get([]byte(keyDeleted))
			if err != nil {
				if errors.Is(err, badger.ErrKeyNotFound) {
					continue
				}
				return err
			}
			delVal, err := delItem.ValueCopy(nil)
			if err != nil {
				return err
			}
			delSlot, err := strconv.ParseUint(string(delVal), 10, 64)
			if err != nil {
				return err
			}
			if delSlot < beforeSlot {
				deleteKeys = append(
					deleteKeys,
					// UTxO key
					key,
					// UTxO "added" key
					[]byte(string(key)+`_added`),
					// UTxO "deleted" key
					[]byte(string(key)+`_deleted`),
				)
			}
		}
		// We delete the keys outside of the iterator, because apparently you can't delete
		// the current key when iterating
		for _, key := range deleteKeys {
			if err := txn.Delete([]byte(key)); err != nil {
				// Leave the rest for the next run if we hit the max transaction size
				if errors.Is(err, badger.ErrTxnTooBig) {
					slog.Debug(
						"purge deleted UTxOs: badger transaction too large, leaving remainder until next run",
					)
					break
				}
				return err
			}
			slog.Debug(
				fmt.Sprintf("purged deleted UTxO key: %s", key),
			)
		}
		return nil
	})
	return err
}

func GetStorage() *Storage {
	return globalStorage
}

// BadgerLogger is a wrapper type to give our logger the expected interface
type BadgerLogger struct{}

func NewBadgerLogger() *BadgerLogger {
	return &BadgerLogger{}
}

func (b *BadgerLogger) Infof(msg string, args ...any) {
	slog.Info(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Warningf(msg string, args ...any) {
	slog.Warn(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Debugf(msg string, args ...any) {
	slog.Debug(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Errorf(msg string, args ...any) {
	slog.Error(
		fmt.Sprintf(msg, args...),
	)
}
