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

package storage

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/blinklabs-io/bluefin/internal/config"

	mpf "github.com/blinklabs-io/merkle-patricia-forestry"
	"github.com/dgraph-io/badger/v4"
	"golang.org/x/crypto/blake2b"
)

type Trie struct {
	sync.Mutex
	db        *badger.DB
	trie      *mpf.Trie
	keyPrefix []byte
}

func NewTrie(db *badger.DB, keyPrefix string) (*Trie, error) {
	t := &Trie{
		db:        db,
		trie:      mpf.NewTrie(),
		keyPrefix: []byte(keyPrefix),
	}
	if err := t.load(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Trie) load() error {
	// Load seed keys
	profile := config.GetProfile()
	for _, seedHash := range profile.SeedHashes {
		seedHashBytes, err := hex.DecodeString(seedHash)
		if err != nil {
			return err
		}
		trieKey := t.HashKey(seedHashBytes)
		if err := t.Update(trieKey, seedHashBytes); err != nil {
			return err
		}
	}
	// Load values from storage
	dbKeyPrefix := t.dbKeyPrefix(nil)
	err := t.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(dbKeyPrefix); it.ValidForPrefix(dbKeyPrefix); it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			// Insert key/value into trie
			tmpKey := strings.TrimPrefix(
				string(item.Key()),
				string(dbKeyPrefix),
			)
			t.trie.Set([]byte(tmpKey), val)
		}
		return nil
	})
	return err
}

func (t *Trie) Update(key []byte, val []byte) error {
	// Update trie
	t.trie.Set(key, val)
	// Update storage
	dbKey := t.dbKeyPrefix(key)
	err := t.db.Update(func(txn *badger.Txn) error {
		return txn.Set(dbKey, val)
	})
	return err
}

func (t *Trie) Delete(key []byte) error {
	// Update trie
	if err := t.trie.Delete(key); err != nil {
		return err
	}
	// Update storage
	dbKey := t.dbKeyPrefix(key)
	err := t.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(dbKey)
	})
	return err
}

func (t *Trie) Hash() []byte {
	return t.trie.Hash().Bytes()
}

func (t *Trie) Prove(key []byte) (*mpf.Proof, error) {
	return t.trie.Prove(key)
}

// HashKey returns a blake2b-256 hash for use in key values
func (t *Trie) HashKey(key []byte) []byte {
	tmpHash, err := blake2b.New256(nil)
	if err != nil {
		// This should never happen
		panic(err.Error())
	}
	tmpHash.Write(key)
	trieKey := tmpHash.Sum(nil)
	return trieKey
}

func (t *Trie) dbKeyPrefix(key []byte) []byte {
	return []byte(
		fmt.Sprintf(
			"trie_%s_%s",
			t.keyPrefix,
			key,
		),
	)
}

func HashValue(val []byte) mpf.Hash {
	return mpf.HashValue(val)
}
