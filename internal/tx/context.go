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

package tx

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Salvionied/apollo/serialization/UTxO"
	"github.com/Salvionied/apollo/txBuilding/Backend/Base"
	"github.com/Salvionied/apollo/txBuilding/Backend/FixedChainContext"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/gouroboros/cbor"
)

// CustomChainContext allows Apollo to lookup script ref UTxOs from our storage
type CustomChainContext struct {
	Base.ChainContext
}

func NewCustomChainContext() CustomChainContext {
	return CustomChainContext{
		ChainContext: FixedChainContext.InitFixedChainContext(),
	}
}

func (c CustomChainContext) GetUtxoFromRef(
	txHash string,
	txIndex int,
) *UTxO.UTxO {
	var ret UTxO.UTxO
	store := storage.GetStorage()
	store.Lock()
	utxoBytes, err := store.GetScriptRefUtxo(txHash, txIndex)
	if err != nil {
		slog.Error(
			fmt.Sprintf("failed to get script ref UTxO: %s", err),
		)
		slog.Warn(
			"NOTE: this probably means that you need to remove your .bluefin directory to re-sync from scratch",
		)
		os.Exit(1)
	}
	store.Unlock()
	if _, err := cbor.Decode(utxoBytes, &ret); err != nil {
		slog.Error(
			fmt.Sprintf("failed to decode script ref UTxO bytes: %s", err),
		)
		os.Exit(1)
	}
	return &ret
}
