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

package worker

import (
	"math/rand"
	"sync"
	"time"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
)

type Manager struct {
	workerWaitGroup sync.WaitGroup
	doneChan        chan any
	resultChan      chan any
	// TODO
}

type WorkerParams struct {
	// TODO
}

var globalManager = &Manager{
	// TODO
}

func (m *Manager) Reset() {
	m.workerWaitGroup = sync.WaitGroup{}
	m.doneChan = make(chan any)
	m.resultChan = make(chan any)
}

func (m *Manager) Stop() {
	close(m.doneChan)
	m.workerWaitGroup.Wait()
	logging.GetLogger().Infof("stopped workers")
}

func (m *Manager) Start(params WorkerParams) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	// Start workers
	m.Reset()
	logger.Infof("starting %d workers", cfg.Worker.Count)
	for i := 0; i < cfg.Worker.Count; i++ {
		go func(workerIdx int) {
			defer m.workerWaitGroup.Done()
			for {
				// Check for worker shutdown
				select {
				case <-m.doneChan:
					return
				default:
					break
				}
				// TODO: miner here
				randVal := rand.Intn(100)
				if randVal == 42 {
					logger.Infof("worker %d found result", workerIdx)
					m.resultChan <- randVal
				}
				time.Sleep(1 * time.Second)
			}
		}(i)
		m.workerWaitGroup.Add(1)
	}
	// Wait for result
	go func() {
		select {
		case <-m.doneChan:
			return
		case result := <-m.resultChan:
			// TODO: send to tx worker
			// TODO: let the indexer receiving an update to the script's UTxOs restart the workers
			logger.Infof("result = %#v", result)
			// Restart workers as a simple test
			m.Stop()
			m.Start(WorkerParams{})
		}
	}()
}

func GetManager() *Manager {
	return globalManager
}
