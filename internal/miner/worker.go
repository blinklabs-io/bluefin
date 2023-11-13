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

package miner

import (
	"sync"

	"github.com/blinklabs-io/bluefin/internal/common"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/tx"
)

type Manager struct {
	workerWaitGroup sync.WaitGroup
	doneChan        chan any
	resultChan      chan Result
	started         bool
	startMutex      sync.Mutex
	stopMutex       sync.Mutex
}

var globalManager = &Manager{}

func (m *Manager) Reset() {
	m.workerWaitGroup = sync.WaitGroup{}
	m.doneChan = make(chan any)
	m.resultChan = make(chan Result, config.GetConfig().Worker.Count)
}

func (m *Manager) Stop() {
	m.stopMutex.Lock()
	defer m.stopMutex.Unlock()
	if !m.started {
		return
	}
	close(m.doneChan)
	m.workerWaitGroup.Wait()
	close(m.resultChan)
	m.started = false
	logging.GetLogger().Infof("stopped workers")
}

func (m *Manager) Start(blockData common.BlockData) {
	m.startMutex.Lock()
	defer m.startMutex.Unlock()
	if m.started {
		return
	}
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	// Start workers
	m.Reset()
	logger.Infof("starting %d workers", cfg.Worker.Count)
	for i := 0; i < cfg.Worker.Count; i++ {
		miner := New(&(m.workerWaitGroup), m.resultChan, m.doneChan, blockData)
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
				logger.Errorf("failed to submit TX: %s", err)
			}
		}
	}()
	m.started = true
}

func GetManager() *Manager {
	return globalManager
}
