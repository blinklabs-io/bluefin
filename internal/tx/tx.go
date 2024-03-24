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
	models "github.com/blinklabs-io/cardano-models"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/protocol/txsubmission"
	"golang.org/x/crypto/blake2b"

	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/logging"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
)

var ntnTxBytes []byte
var ntnTxHash [32]byte
var ntnSentTx bool
var doneChan chan any

func SendTx(blockData any, nonce [16]byte) error {
	txBytes, err := createTx(blockData, nonce)
	if err != nil {
		return err
	}
	txId, err := submitTx(txBytes)
	if err != nil {
		return err
	}
	logging.GetLogger().Infof("successfully submitted TX %s", txId)
	return nil
}

func createTx(blockData any, nonce [16]byte) ([]byte, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	bursa := wallet.GetWallet()

	profileCfg := config.GetProfile()

	validatorHash := profileCfg.ValidatorHash

	postDatum := PlutusData.PlutusData{
		PlutusDataType: PlutusData.PlutusBytes,
		TagNr:          0,
		Value:          blockData,
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
	tunaPolicyId, err := Policy.New(validatorHash)
	if err != nil {
		return nil, err
	}
	var tunaCount int64
	for _, utxoBytes := range utxosBytes {
		utxo := UTxO.UTxO{}
		if _, err := cbor.Decode(utxoBytes, &utxo); err != nil {
			return nil, err
		}
		// Record the number of TUNA in inputs to use in outputs
		assets := utxo.Output.GetValue().GetAssets()
		if assets != nil {
			tunaCount += assets.GetByPolicyAndId(
				*tunaPolicyId,
				AssetName.NewAssetNameFromString("TUNA"),
			)
		}
		utxos = append(utxos, utxo)
	}

	// Gather UTxO(s) for script
	scriptUtxosBytes, err := storage.GetStorage().
		GetUtxos(cfg.Indexer.ScriptAddress)
	if err != nil {
		return nil, err
	}
	scriptUtxos := []UTxO.UTxO{}
	for _, utxoBytes := range scriptUtxosBytes {
		var utxo UTxO.UTxO
		if _, err := cbor.Decode(utxoBytes, &utxo); err != nil {
			return nil, err
		}
		scriptUtxos = append(scriptUtxos, utxo)
	}
	// There should only ever be 1 UTxO for the script address
	if len(scriptUtxos) > 1 {
		logger.Warnf(
			"found unexpected UTxO(s) at script address (%s), expected 1 and found %d",
			cfg.Indexer.ScriptAddress,
			len(scriptUtxos),
		)
	}
	validatorOutRef := scriptUtxos[0]

	var blockDataRealTimeNow int64
	if profileCfg.UseTunaV1 {
		tmpBlockData := blockData.(models.TunaV1State)
		blockDataRealTimeNow = tmpBlockData.RealTimeNow
	}

	// Determine validity start/end slot based on datum
	datumSlot := unixTimeToSlot(blockDataRealTimeNow / 1000)

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
					Mem:   60_000,
					Steps: 30_000_000,
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
	if profileCfg.ScriptInputRefTxId != "" {
		// Use a script input ref
		apollob = apollob.AddReferenceInput(
			profileCfg.ScriptInputRefTxId,
			int(profileCfg.ScriptInputRefOutIndex),
		)
	} else {
		// Include the script with the TX
		validatorScriptBytes, err := hex.DecodeString(profileCfg.ValidatorScript)
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
	sKeyBytes, err := hex.DecodeString(bursa.PaymentExtendedSKey.CborHex)
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
	networkCfg := config.Networks[cfg.Network]
	return networkCfg.ShelleyOffsetSlot + uint64(
		unixTime-networkCfg.ShelleyOffsetTime,
	)
}

func submitTx(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	if cfg.Submit.Address != "" {
		return submitTxNtN(txRawBytes)
	} else if cfg.Submit.SocketPath != "" {
		return submitTxNtC(txRawBytes)
	} else if cfg.Submit.Url != "" {
		return submitTxApi(txRawBytes)
	} else {
		// Populate address info from indexer network
		network := ouroboros.NetworkByName(cfg.Network)
		if network == ouroboros.NetworkInvalid {
			logger.Fatalf("unknown network: %s", cfg.Network)
		}
		cfg.Submit.Address = fmt.Sprintf("%s:%d", network.PublicRootAddress, network.PublicRootPort)
		return submitTxNtN(txRawBytes)
	}
}

func submitTxNtN(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()

	// Record TX bytes in global for use in handler functions
	ntnTxBytes = txRawBytes[:]
	ntnSentTx = false

	// Generate TX hash
	// Unwrap raw transaction bytes into a CBOR array
	txUnwrap := []cbor.RawMessage{}
	if _, err := cbor.Decode(txRawBytes, &txUnwrap); err != nil {
		logger.Errorf("failed to unwrap transaction CBOR: %s", err)
		return "", fmt.Errorf("failed to unwrap transaction CBOR: %s", err)
	}
	// index 0 is the transaction body
	// Store index 0 (transaction body) as byte array
	txBody := txUnwrap[0]
	// Convert the body into a blake2b256 hash string
	ntnTxHash = blake2b.Sum256(txBody)

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
		ouroboros.WithNetworkMagic(cfg.NetworkMagic),
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
	// Sleep 2s to allow time for TX to enter remote mempool before closing connection
	time.Sleep(2 * time.Second)

	if err := o.Close(); err != nil {
		return "", fmt.Errorf("failed to close connection: %s", err)
	}

	return hex.EncodeToString(ntnTxHash[:]), nil
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
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf(
			"failed to send request: %s: %s",
			cfg.Submit.Url,
			err,
		)
	}
	if resp == nil {
		return "", fmt.Errorf(
			"failed parsing empty response from: %s",
			cfg.Submit.Url,
		)
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

func handleRequestTxIds(
	blocking bool,
	ack uint16,
	req uint16,
) ([]txsubmission.TxIdAndSize, error) {
	if ntnSentTx {
		// Terrible syncronization hack for shutdown
		close(doneChan)
		time.Sleep(5 * time.Second)
		return nil, nil
	}
	ret := []txsubmission.TxIdAndSize{
		{
			TxId: txsubmission.TxId{
				EraId: 5,
				TxId:  ntnTxHash,
			},
			Size: uint32(len(ntnTxBytes)),
		},
	}
	return ret, nil
}

func handleRequestTxs(
	txIds []txsubmission.TxId,
) ([]txsubmission.TxBody, error) {
	ret := []txsubmission.TxBody{
		{
			EraId:  5,
			TxBody: ntnTxBytes,
		},
	}
	ntnSentTx = true
	return ret, nil
}
