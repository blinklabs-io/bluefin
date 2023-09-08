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

package wallet

import (
	"errors"
	"os"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"

	"github.com/blinklabs-io/bursa"
)

var globalWallet = &bursa.Wallet{}

func Setup() {
	// Setup wallet
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	// TODO: check storage for mnemonic
	mnemonic := cfg.Wallet.Mnemonic
	if mnemonic == "" {
		// Read seed.txt if it exists
		if data, err := os.ReadFile("seed.txt"); err == nil {
			logger.Infof("read mnemonic from seed.txt")
			mnemonic = string(data)
		} else if errors.Is(err, os.ErrNotExist) {
			mnemonic, err = bursa.NewMnemonic()
			if err != nil {
				panic(err)
			}
			// Write seed.txt
			// WARNING: this will clobber existing files
			f, err := os.Create("seed.txt")
			if err != nil {
				panic(err)
			}
			l, err := f.WriteString(mnemonic)
			logger.Debugf("wrote %d bytes to seed.txt", l)
			if err != nil {
				f.Close()
				panic(err)
			}
			err = f.Close()
			if err != nil {
				panic(err)
			}
			logger.Infof("wrote generated mnemonic to seed.txt")
			// TODO: write mnemonic to storage
		} else {
			panic(err)
		}
	}
	rootKey, err := bursa.GetRootKeyFromMnemonic(mnemonic)
	if err != nil {
		panic(err)
	}
	accountKey := bursa.GetAccountKey(rootKey, 0)
	paymentKey := bursa.GetPaymentKey(accountKey, 0)
	stakeKey := bursa.GetStakeKey(accountKey, 0)
	addr := bursa.GetAddress(accountKey, cfg.Indexer.Network, 0)
	wallet := &bursa.Wallet{
		Mnemonic:       mnemonic,
		PaymentAddress: addr.String(),
		StakeAddress:   addr.ToReward().String(),
		PaymentVKey:    bursa.GetPaymentVKey(paymentKey),
		PaymentSKey:    bursa.GetPaymentSKey(paymentKey),
		StakeVKey:      bursa.GetStakeVKey(stakeKey),
		StakeSKey:      bursa.GetStakeVKey(stakeKey),
	}
	globalWallet = wallet
}

func GetWallet() *bursa.Wallet {
	return globalWallet
}
