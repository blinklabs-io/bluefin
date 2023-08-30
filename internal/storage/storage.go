package storage

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
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

// TODO: add other helper functions for storage data

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
