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

package metrics

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
)

var (
	hashesProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bluefin_hashes_processed_total",
		Help: "The total number of hashes processed",
	},[]string{})
)

func GetHashes() prometheus.Counter {
	return hashesProcessed
}

func hashTimer() {
	var hashes float64
	var initialHashes uint32 = 0
	var counterHashes uint32 = 0
	logger := logging.GetLogger()
	go func() {
		for {
			initialHashes = counterHashes
			time.Sleep(60*time.Second)
			hashes = float64((counterHashes - initialHashes))/60
			logger.Infof("hashes per second: %.4f", hashes)
		}
	}()
}

func Start() error {
	cfg := config.GetConfig()
	hashTimer()
	http.Handle("/", promhttp.Handler())
	go http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.Metrics.Address, cfg.Metrics.Port), nil)
	return nil
}
