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
	"fmt"
	"net"
	"time"

	"github.com/Salvionied/apollo"
	serAddress "github.com/Salvionied/apollo/serialization/Address"
	"github.com/Salvionied/apollo/serialization/Key"
	"github.com/Salvionied/apollo/serialization/PlutusData"
	"github.com/Salvionied/apollo/serialization/Redeemer"
	"github.com/Salvionied/apollo/serialization/UTxO"
	"github.com/Salvionied/cbor/v2"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/protocol/txsubmission"
	"golang.org/x/crypto/blake2b"

	"github.com/blinklabs-io/bluefin/internal/common"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
)

var txBytes []byte
var txHash [32]byte
var sentTx bool
var doneChan chan any

func SendTx(blockData common.BlockData, nonce [16]byte) error {
	txBytes, err := createTx(blockData, nonce)
	if err != nil {
		return err
	}
	txId, err := submitTx(txBytes)
	if err != nil {
		return err
	}
	logging.GetLogger().Infof("successfully submitted TX %x", txId)
	return nil
}

func createTx(blockData common.BlockData, nonce [16]byte) ([]byte, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()

	networkCfg := config.NetworkMap[cfg.Indexer.Network]

	validatorHash := networkCfg.ValidatorHash

	// Get current slot
	currentTipSlotNumber, _, err := storage.GetStorage().GetCursor()
	if err != nil {
		return nil, err
	}

	pdInterlink := PlutusData.PlutusIndefArray{}
	for _, val := range blockData.Interlink {
		pdInterlink = append(pdInterlink, PlutusData.PlutusData{
			PlutusDataType: PlutusData.PlutusBytes,
			Value:          val})
	}

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

	contractAddress, _ := serAddress.DecodeAddress(cfg.Indexer.ScriptAddress)
	myAddress, _ := serAddress.DecodeAddress(bursa.PaymentAddress)
	cc := apollo.NewEmptyBackend()
	apollob := apollo.New(&cc)
	apollob = apollob.
		SetWalletFromBech32(bursa.PaymentAddress).
		SetWalletAsChangeAddress()

	// Gather input UTxOs from our wallet
	utxosBytes, err := storage.GetStorage().GetUtxos(bursa.PaymentAddress)
	if err != nil {
		return nil, err
	}
	var utxos []UTxO.UTxO
	for _, utxoBytes := range utxosBytes {
		var utxo UTxO.UTxO
		if err := cbor.Unmarshal(utxoBytes, &utxo); err != nil {
			return nil, err
		}
		utxos = append(utxos, utxo)
	}

	// Gather UTxO(s) for script
	scriptUtxosBytes, err := storage.GetStorage().GetUtxos(cfg.Indexer.ScriptAddress)
	if err != nil {
		return nil, err
	}
	var scriptUtxos []UTxO.UTxO
	for _, utxoBytes := range scriptUtxosBytes {
		var utxo UTxO.UTxO
		if err := cbor.Unmarshal(utxoBytes, &utxo); err != nil {
			return nil, err
		}
		scriptUtxos = append(scriptUtxos, utxo)
	}
	// There should only ever be 1 UTxO for the script address
	if len(scriptUtxos) > 1 {
		logger.Warnf("found unexpected UTxO(s) at script address (%s), expected 1 and found %d", cfg.Indexer.ScriptAddress, len(scriptUtxos))
	}
	validatorOutRef := scriptUtxos[0]

	apollob = apollob.AddLoadedUTxOs(utxos...)
	apollob = apollob.
		PayToContract(contractAddress, &postDatum, int(validatorOutRef.Output.Lovelace()), true, apollo.NewUnit(validatorHash, "lord tuna", 1)).
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
		CollectFrom(
			validatorOutRef,
			Redeemer.Redeemer{
				Tag: Redeemer.SPEND,
				Data: PlutusData.PlutusData{
					PlutusDataType: PlutusData.PlutusArray,
					TagNr:          122,
					Value: PlutusData.PlutusIndefArray{
						PlutusData.PlutusData{
							PlutusDataType: PlutusData.PlutusBytes,
							Value:          nonce,
						}},
				},
			},
		)
	if networkCfg.ScriptInputRefTxId != "" {
		// Use a script input ref
		apollob = apollob.AddReferenceInput(networkCfg.ScriptInputRefTxId, int(networkCfg.ScriptInputRefOutIndex))
	} else {
		// Include the script with the TX
		validatorScriptBytes, err := hex.DecodeString(networkCfg.ValidatorScript)
		if err != nil {
			return nil, err
		}
		apollob = apollob.AttachV2Script(PlutusData.PlutusV2Script(validatorScriptBytes))
	}
	tx, err := apollob.Complete()
	if err != nil {
		return nil, err
	}

	vKeyBytes, err := hex.DecodeString(bursa.PaymentVKey.CborHex)
	if err != nil {
		return nil, err
	}
	sKeyBytes, err := hex.DecodeString(bursa.PaymentSKey.CborHex)
	if err != nil {
		return nil, err
	}
	// Strip off leading 2 bytes as shortcut for CBOR decoding to unwrap bytes
	vKeyBytes = vKeyBytes[2:]
	sKeyBytes = sKeyBytes[2:]
	vkey := Key.VerificationKey{Payload: vKeyBytes}
	skey := Key.SigningKey{Payload: sKeyBytes[:64]}
	tx = tx.SignWithSkey(vkey, skey)
	return tx.GetTx().Bytes(), nil
}

func submitTx(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	logger.Infof("debug: %s", txBytes)

	// Generate TX hash
	// Unwrap raw transaction bytes into a CBOR array
	var txUnwrap []cbor.RawMessage
	if err := cbor.Unmarshal(txRawBytes, &txUnwrap); err != nil {
		logger.Errorf("failed to unwrap transaction CBOR: %s", err)
		return "", fmt.Errorf("failed to unwrap transaction CBOR: %s", err)
	}
	// index 0 is the transaction body
	// Store index 0 (transaction body) as byte array
	txBody := txUnwrap[0]
	// Convert the body into a blake2b256 hash string
	txHash = blake2b.Sum256(txBody)

	// Create connection
	var networkMagic uint32
	// Lookup network by name
	network := ouroboros.NetworkByName(cfg.Indexer.Network)
	if network == ouroboros.NetworkInvalid {
		logger.Errorf("unknown network: %s", cfg.Indexer.Network)
		panic(fmt.Errorf("unknown network: %s", cfg.Indexer.Network))
	}
	networkMagic = network.NetworkMagic
	nodeAddress := fmt.Sprintf("%s:%d", network.PublicRootAddress, network.PublicRootPort)

	conn := createClientConnection(nodeAddress)
	errorChan := make(chan error)
	// Capture errors
	go func() {
		for {
			err := <-errorChan
			panic(fmt.Errorf("async: %s", err))
		}
	}()
	o, err := ouroboros.New(
		ouroboros.WithConnection(conn),
		ouroboros.WithNetworkMagic(uint32(networkMagic)),
		ouroboros.WithErrorChan(errorChan),
		ouroboros.WithNodeToNode(true),
		ouroboros.WithKeepAlive(true),
		ouroboros.WithTxSubmissionConfig(
			txsubmission.NewConfig(
				txsubmission.WithRequestTxIdsFunc(handleRequestTxIds),
				txsubmission.WithRequestTxsFunc(handleRequestTxs),
			),
		),
	)
	if err != nil {
		return "", err
	}

	// Start txSubmission loop
	doneChan = make(chan any)
	o.TxSubmission().Client.Init()
	<-doneChan

	if err := o.Close(); err != nil {
		return "", fmt.Errorf("failed to close connection: %s", err)
	}

	return string(txHash[:]), nil
}

func createClientConnection(nodeAddress string) net.Conn {
	logger := logging.GetLogger()
	var err error
	var conn net.Conn
	var dialProto string
	var dialAddress string
	dialProto = "tcp"
	dialAddress = nodeAddress

	conn, err = net.Dial(dialProto, dialAddress)
	if err != nil {
		logger.Errorf("connection failed: %s", err)
		panic(err)
	}
	return conn
}

func handleRequestTxIds(blocking bool, ack uint16, req uint16) ([]txsubmission.TxIdAndSize, error) {
	if sentTx {
		// Terrible syncronization hack for shutdown
		close(doneChan)
		time.Sleep(5 * time.Second)
	}
	ret := []txsubmission.TxIdAndSize{
		{
			TxId: txsubmission.TxId{
				EraId: 5,
				TxId:  txHash,
			},
			Size: uint32(len(txBytes)),
		},
	}
	return ret, nil
}

func handleRequestTxs(txIds []txsubmission.TxId) ([]txsubmission.TxBody, error) {
	ret := []txsubmission.TxBody{
		{
			EraId:  5,
			TxBody: txBytes,
		},
	}
	sentTx = true
	return ret, nil
}
