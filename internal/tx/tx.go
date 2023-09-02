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

package tx

import (
	"encoding/hex"

	"github.com/Salvionied/apollo"
	serAddress "github.com/Salvionied/apollo/serialization/Address"
	"github.com/Salvionied/apollo/serialization/Key"
	"github.com/Salvionied/apollo/serialization/PlutusData"
	"github.com/Salvionied/apollo/serialization/Redeemer"
	"github.com/Salvionied/apollo/serialization/UTxO"
	"github.com/Salvionied/cbor/v2"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/miner"
	"github.com/blinklabs-io/bluefin/internal/wallet"
)

func SendTx() {
	createTx([][]byte{})
}

func createTx(utxosBytes [][]byte) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()

	// TODO: get these from elsewhere
	validatorHash := "123456" // from genesis
	currentTipSlotNumber := 1234
	refInputHash := "01751095ea408a3ebe6083b4de4de8a24b635085183ab8a2ac76273ef8fff5dd"
	refInputId := 0
	ValidatorOutRef := UTxO.UTxO{}
	Nonce := "12345"
	blockData := miner.BlockData{}

	pdInterlink := PlutusData.PlutusIndefArray{}
	for _, val := range blockData.Interlink {
		pdInterlink = append(pdInterlink, PlutusData.PlutusData{
			PlutusDataType: PlutusData.PlutusBytes,
			Value:          val})
	}
	utxoBytes := []byte("foo")

	pd := PlutusData.PlutusData{
		TagNr:          121,
		PlutusDataType: PlutusData.PlutusArray,
		Value: PlutusData.PlutusIndefArray{
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.BlockNumber + 1},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				Value:          blockData.TargetHash},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.LeadingZeros},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.DifficultyNumber},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.EpochTime}, //NEEDS FIXING
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.RealTimeNow + 90000},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				Value:          []byte(blockData.Message)},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusArray,
				Value:          pdInterlink},
		}}

	marshaled, _ := cbor.Marshal(pd)
	postDatum := PlutusData.PlutusData{
		PlutusDataType: PlutusData.PlutusArray,
		Value: []PlutusData.PlutusData{
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          1,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				TagNr:          24,
				Value:          marshaled,
			}}}

	// TODO: apollo
	contractAddress, _ := serAddress.DecodeAddress(cfg.Indexer.ScriptAddress)
	myAddress, _ := serAddress.DecodeAddress(bursa.PaymentAddress)
	cc := apollo.NewEmptyBackend()
	apollob := apollo.New(&cc)
	apollob = apollob.
		SetWalletFromBech32(bursa.PaymentAddress).
		SetWalletAsChangeAddress()
	var utxos []UTxO.UTxO
	for _, u := range utxoBytes {
		var utxo UTxO.UTxO
		str, _ := hex.DecodeString(string(u))
		_ = cbor.Unmarshal(str, &utxo)
		utxos = append(utxos, utxo)
	}
	apollob = apollob.AddLoadedUTxOs(utxos...)
	apollob = apollob.
		PayToContract(contractAddress, &postDatum, int(ValidatorOutRef.Output.Lovelace()), true, apollo.NewUnit(validatorHash, "lord tuna", 1)).
		SetTtl(int64(currentTipSlotNumber+180000)).
		PayToAddress(myAddress, 2000000, apollo.NewUnit(validatorHash, "TUNA", 5000000000)).
		SetValidityStart(int64(currentTipSlotNumber)).MintAssetsWithRedeemer(
		apollo.NewUnit(validatorHash, "TUNA", 5000000000),
		Redeemer.Redeemer{
			Tag:   Redeemer.MINT,
			Index: 0,
			Data: PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusArray,
				TagNr:          121,
				Value:          PlutusData.PlutusIndefArray{},
			},
		}).
		AddReferenceInput(refInputHash, refInputId).
		CollectFrom(
			ValidatorOutRef,
			Redeemer.Redeemer{
				Tag: Redeemer.SPEND,
				Data: PlutusData.PlutusData{
					PlutusDataType: PlutusData.PlutusArray,
					TagNr:          122,
					Value: PlutusData.PlutusIndefArray{
						PlutusData.PlutusData{
							PlutusDataType: PlutusData.PlutusBytes,
							Value:          Nonce,
						}},
				},
			},
		)
	tx, err := apollob.Complete()
	if err != nil {
		panic(err)
	}

	// TODO: get the proper type from apollo
	vKeyBytes, err := hex.DecodeString(bursa.PaymentVKey.CborHex)
	if err != nil {
		panic(err)
	}
	sKeyBytes, err := hex.DecodeString(bursa.PaymentSKey.CborHex)
	if err != nil {
		panic(err)
	}
	vkey := Key.VerificationKey{Payload: vKeyBytes}
	skey := Key.SigningKey{Payload: sKeyBytes}
	tx = tx.SignWithSkey(vkey, skey)
	logger.Infof("submitting block...")
	txId, err := SendToSubmitAPI(tx.GetTx().Bytes())
	if err != nil {
		panic(err)
	}

	logger.Infof("fake tx id %s from %s to %s", txId, myAddress.String(), contractAddress.String())
}

func SendToSubmitAPI(cborBytes []byte) (string, error) {
	logger := logging.GetLogger()
	logger.Infof("debug: %s", cborBytes)
	return "", nil
}
