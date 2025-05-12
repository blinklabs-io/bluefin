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

package miner

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/tx"
)

const (
	restartTimeout = 2 * time.Minute
)

type Manager struct {
	workerWaitGroup  sync.WaitGroup
	doneChan         chan any
	resultChan       chan Result
	started          bool
	startMutex       sync.Mutex
	stopMutex        sync.Mutex
	hashCounter      *atomic.Uint64
	hashLogTimer     *time.Timer
	hashLogLastCount uint64
	restartTimer     *time.Timer
	lastBlockData    any
}

var globalManager = &Manager{}

func (m *Manager) Reset() {
	m.workerWaitGroup = sync.WaitGroup{}
	m.doneChan = make(chan any)
	m.resultChan = make(chan Result, config.GetConfig().Miner.WorkerCount)
}

func (m *Manager) Stop() {
	m.stopMutex.Lock()
	defer m.stopMutex.Unlock()
	if !m.started {
		return
	}
	if m.hashLogTimer != nil {
		m.hashLogTimer.Stop()
	}
	close(m.doneChan)
	m.workerWaitGroup.Wait()
	close(m.resultChan)
	m.started = false
	slog.Info("stopped workers")
	// Start timer to restart miner
	m.restartTimer = time.AfterFunc(
		restartTimeout,
		func() {
			slog.Warn(
				fmt.Sprintf(
					"restarting miner automatically after %s timeout",
					restartTimeout,
				),
			)
			m.Start(m.lastBlockData)
		},
	)
}

func (m *Manager) Start(blockData any) {
	m.startMutex.Lock()
	defer m.startMutex.Unlock()
	if m.started {
		return
	}
	m.lastBlockData = blockData
	// Cancel any restart timer
	if m.restartTimer != nil {
		m.restartTimer.Stop()
	}
	cfg := config.GetConfig()
	// Start hash rate log timer
	m.hashCounter = &atomic.Uint64{}
	m.scheduleHashRateLog()
	// Start workers
	m.Reset()
	slog.Info(
		fmt.Sprintf("starting %d workers", cfg.Miner.WorkerCount),
	)
	for range cfg.Miner.WorkerCount {
		miner := New(
			&(m.workerWaitGroup),
			m.resultChan,
			m.doneChan,
			blockData,
			m.hashCounter,
		)
		m.workerWaitGroup.Add(1)
		go miner.Start()
	}
	// Wait for result
	go func() {
		select {
		case <-m.doneChan:
			return
		case result := <-m.resultChan:
			// Stop workers until our result makes it on-chain
			m.Stop()
			// Build and submit the TX
			if err := tx.SendTx(result.BlockData, result.Nonce); err != nil {
				slog.Error(
					fmt.Sprintf("failed to submit TX: %s", err),
				)
			}
		}
	}()
	m.started = true
}

func (m *Manager) scheduleHashRateLog() {
	cfg := config.GetConfig()
	m.hashLogTimer = time.AfterFunc(
		time.Duration(cfg.Miner.HashRateInterval)*time.Second,
		m.hashRateLog,
	)
}

func (m *Manager) hashRateLog() {
	cfg := config.GetConfig()
	hashCount := m.hashCounter.Load()
	// Handle counter rollover
	if hashCount < m.hashLogLastCount {
		m.hashLogLastCount = 0
		m.scheduleHashRateLog()
		return
	}
	hashCountDiff := hashCount - m.hashLogLastCount
	m.hashLogLastCount = hashCount
	secondDivisor := uint64(cfg.Miner.HashRateInterval) // #nosec G115
	hashCountPerSec := hashCountDiff / secondDivisor
	slog.Info(
		fmt.Sprintf("hash rate: %d/s", hashCountPerSec),
	)
	m.scheduleHashRateLog()
}

func GetManager() *Manager {
	return globalManager
}
