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

package wallet

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/blinklabs-io/bluefin/internal/config"
	"golang.org/x/crypto/blake2b"

	"github.com/blinklabs-io/bursa"
)

var globalWallet = &bursa.Wallet{}

func Setup() {
	// Setup wallet
	cfg := config.GetConfig()
	// TODO: check storage for mnemonic
	mnemonic := cfg.Wallet.Mnemonic
	if mnemonic == "" {
		pwd, err := os.Getwd()
		if err != nil {
			panic(err.Error())
		}
		seedPath := path.Join(
			pwd,
			"seed.txt",
		)
		// Read seed.txt if it exists
		if data, err := os.ReadFile(seedPath); err == nil {
			slog.Info(
				fmt.Sprintf("read mnemonic from %s", seedPath),
			)
			mnemonic = string(data)
		} else if errors.Is(err, os.ErrNotExist) {
			mnemonic, err = bursa.NewMnemonic()
			if err != nil {
				panic(err)
			}
			// Write seed.txt
			// WARNING: this will clobber existing files
			f, err := os.Create(seedPath)
			if err != nil {
				panic(err)
			}
			l, err := f.WriteString(mnemonic)
			slog.Debug(
				fmt.Sprintf("wrote %d bytes to seed.txt", l),
			)
			if err != nil {
				f.Close()
				panic(err)
			}
			err = f.Close()
			if err != nil {
				panic(err)
			}
			slog.Info(
				fmt.Sprintf("wrote generated mnemonic to %s", seedPath),
			)
			// TODO: write mnemonic to storage
		} else {
			panic(err)
		}
	}
	wallet, err := bursa.NewWallet(
		mnemonic,
		cfg.Network,
		"", 0, 0, 0, 0,
	)
	if err != nil {
		panic(err)
	}
	globalWallet = wallet
}

func GetWallet() *bursa.Wallet {
	return globalWallet
}

func PaymentKeyHash() []byte {
	rootKey, err := bursa.GetRootKeyFromMnemonic(globalWallet.Mnemonic, "")
	if err != nil {
		panic(err)
	}
	userPkh := bursa.GetPaymentKey(bursa.GetAccountKey(rootKey, 0), 0).
		Public().
		PublicKey()
	tmpHasher, err := blake2b.New(28, nil)
	if err != nil {
		panic(err)
	}
	tmpHasher.Write(userPkh)
	hash := tmpHasher.Sum(nil)
	return hash
}
