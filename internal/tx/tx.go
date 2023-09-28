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
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Salvionied/apollo"
	serAddress "github.com/Salvionied/apollo/serialization/Address"
	"github.com/Salvionied/apollo/serialization/AssetName"
	"github.com/Salvionied/apollo/serialization/Key"
	"github.com/Salvionied/apollo/serialization/PlutusData"
	"github.com/Salvionied/apollo/serialization/Policy"
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
	fmt.Printf("txBytes = %x\n", txBytes)
	/*
		var txUnwrap []cbor.RawMessage
		if err := cbor.Unmarshal(txBytes, &txUnwrap); err != nil {
			return err
		}
		fmt.Printf("txBody = %x\n", txUnwrap[0])
	*/
	txId, err := submitTx(txBytes)
	if err != nil {
		return err
	}
	logging.GetLogger().Infof("successfully submitted TX %x", txId)
	return nil
}

func createTx(blockData common.BlockData, nonce [16]byte) ([]byte, error) {
	//fmt.Printf("createTx(): nonce=%x, blockData = %#v\n", nonce, blockData)
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()

	networkCfg := config.NetworkMap[cfg.Indexer.Network]

	validatorHash := networkCfg.ValidatorHash

	/*
		// Get current slot
		currentTipSlotNumber, _, err := storage.GetStorage().GetCursor()
		if err != nil {
			return nil, err
		}
	*/

	pdInterlink := PlutusData.PlutusIndefArray{}
	for _, val := range blockData.Interlink {
		pdInterlink = append(
			pdInterlink,
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				Value:          val,
			},
		)
	}

	pd := PlutusData.PlutusData{
		TagNr:          121,
		PlutusDataType: PlutusData.PlutusArray,
		Value: PlutusData.PlutusIndefArray{
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.BlockNumber,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				Value:          blockData.TargetHash,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.LeadingZeros,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.DifficultyNumber,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.EpochTime, //NEEDS FIXING (?)
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusInt,
				Value:          blockData.RealTimeNow,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				Value:          blockData.Message,
			},
			PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusArray,
				Value:          pdInterlink,
			},
		},
	}

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
			},
		},
	}

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
	tunaPolicyId, _ := Policy.New(validatorHash)
	var tunaCount int64
	for _, utxoBytes := range utxosBytes {
		var utxo UTxO.UTxO
		if err := cbor.Unmarshal(utxoBytes, &utxo); err != nil {
			return nil, err
		}
		/*
			if hex.EncodeToString(utxo.Input.TransactionId) == "01cd3419f8e224409059bc17a67f995cc0d98e3ab8df70b5d4e98f14f363b582" {
				if utxo.Input.Index != 0 {
					continue
				}
			} else if hex.EncodeToString(utxo.Input.TransactionId) == "51fc0f925d714add1fb3c1b583fc935b8b83d9fa79c5f6b3f2f5e4c13b1b2ff9" {
				if utxo.Input.Index != 1 {
					continue
				}
			} else {
				continue
			}
		*/
		// Record the number of TUNA in inputs to use in outputs
		tunaCount += utxo.Output.GetValue().GetAssets().GetByPolicyAndId(*tunaPolicyId, AssetName.NewAssetNameFromString("TUNA"))
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

	// Determine validity start/end slot based on datum
	datumSlot := unixTimeToSlot(blockData.RealTimeNow / 1000)

	apollob = apollob.AddLoadedUTxOs(utxos...)
	apollob = apollob.
		PayToContract(
			contractAddress, &postDatum, int(validatorOutRef.Output.PostAlonzo.Amount.Am.Coin), true, apollo.NewUnit(validatorHash, "lord tuna", 1),
		).
		SetValidityStart(int64(datumSlot-90)).
		SetTtl(int64(datumSlot+90)).
		PayToAddress(
			myAddress, 2000000, apollo.NewUnit(validatorHash, "TUNA", int(tunaCount+5000000000)),
		).
		MintAssetsWithRedeemer(
			apollo.NewUnit(validatorHash, "TUNA", 5000000000),
			Redeemer.Redeemer{
				Tag:   Redeemer.MINT,
				Index: 0,
				// NOTE: these values are estimated
				ExUnits: Redeemer.ExecutionUnits{
					Mem:   50_000,
					Steps: 20_000_000,
				},
				Data: PlutusData.PlutusData{
					PlutusDataType: PlutusData.PlutusArray,
					TagNr:          121,
					Value:          PlutusData.PlutusIndefArray{},
				},
			},
		).
		CollectFrom(
			validatorOutRef,
			Redeemer.Redeemer{
				Tag: Redeemer.SPEND,
				// NOTE: these values are estimated
				ExUnits: Redeemer.ExecutionUnits{
					Mem:   450_000,
					Steps: 200_000_000,
				},
				Data: PlutusData.PlutusData{
					PlutusDataType: PlutusData.PlutusArray,
					TagNr:          122,
					Value: PlutusData.PlutusIndefArray{
						PlutusData.PlutusData{
							PlutusDataType: PlutusData.PlutusBytes,
							Value:          nonce,
						},
					},
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
	// Strip out public key portion of extended private key
	sKeyBytes = append(sKeyBytes[:64], sKeyBytes[96:]...)
	vkey := Key.VerificationKey{Payload: vKeyBytes}
	skey := Key.SigningKey{Payload: sKeyBytes}
	tx, err = tx.SignWithSkey(vkey, skey)
	if err != nil {
		return nil, err
	}
	txBytes, err := tx.GetTx().Bytes()
	if err != nil {
		return nil, err
	}
	return txBytes, nil
}

func unixTimeToSlot(unixTime int64) uint64 {
	cfg := config.GetConfig()
	networkCfg := config.NetworkMap[cfg.Indexer.Network]
	return networkCfg.ShelleyOffsetSlot + uint64(unixTime-networkCfg.ShelleyOffsetTime)
}

func submitTx(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	if cfg.Submit.NetworkMagic == 0 {
		// Populate network magic from indexer network
		network := ouroboros.NetworkByName(cfg.Indexer.Network)
		if network == ouroboros.NetworkInvalid {
			logger.Fatalf("unknown network: %s", cfg.Indexer.Network)
		}
		cfg.Submit.NetworkMagic = network.NetworkMagic
	}
	if cfg.Submit.Address != "" {
		return submitTxNtN(txRawBytes)
	} else if cfg.Submit.SocketPath != "" {
		return submitTxNtC(txRawBytes)
	} else if cfg.Submit.Url != "" {
		return submitTxApi(txRawBytes)
	} else {
		// Populate address info from indexer network
		network := ouroboros.NetworkByName(cfg.Indexer.Network)
		if network == ouroboros.NetworkInvalid {
			logger.Fatalf("unknown network: %s", cfg.Indexer.Network)
		}
		cfg.Submit.Address = fmt.Sprintf("%s:%d", network.PublicRootAddress, network.PublicRootPort)
		return submitTxNtN(txRawBytes)
	}
}

func submitTxNtN(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	//logger.Infof("debug: %s", txBytes)

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
	conn := createClientConnection(cfg.Submit.Address)
	errorChan := make(chan error)
	// Capture errors
	go func() {
		err, ok := <-errorChan
		if ok {
			panic(fmt.Errorf("async: %s", err))
		}
	}()
	o, err := ouroboros.New(
		ouroboros.WithConnection(conn),
		ouroboros.WithNetworkMagic(cfg.Submit.NetworkMagic),
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

func submitTxNtC(txRawBytes []byte) (string, error) {
	// TODO
	return "", nil
}

func submitTxApi(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	reqBody := bytes.NewBuffer(txRawBytes)
	req, err := http.NewRequest(http.MethodPost, cfg.Submit.Url, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %s", err)
	}
	req.Header.Add("Content-Type", "application/cbor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %s: %s", cfg.Submit.Url, err)
	}
	// We have to read the entire response body and close it to prevent a memory leak
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 202 {
		return string(respBody), nil
	} else {
		return "", fmt.Errorf("failed to submit TX to API: %s: %d: %s", cfg.Submit.Url, resp.StatusCode, respBody)
	}
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
