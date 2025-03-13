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

package tx

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Salvionied/apollo"
	"github.com/Salvionied/apollo/serialization"
	serAddress "github.com/Salvionied/apollo/serialization/Address"
	"github.com/Salvionied/apollo/serialization/AssetName"
	"github.com/Salvionied/apollo/serialization/Key"
	"github.com/Salvionied/apollo/serialization/PlutusData"
	"github.com/Salvionied/apollo/serialization/Policy"
	"github.com/Salvionied/apollo/serialization/Redeemer"
	"github.com/Salvionied/apollo/serialization/UTxO"
	"github.com/blinklabs-io/bluefin/internal/config"
	"github.com/blinklabs-io/bluefin/internal/storage"
	"github.com/blinklabs-io/bluefin/internal/wallet"
	models "github.com/blinklabs-io/cardano-models"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/protocol/txsubmission"
	"golang.org/x/crypto/blake2b"
)

var (
	ntnTxBytes []byte
	ntnTxHash  [32]byte
	ntnSentTx  bool
	ntnMutex   sync.Mutex
	doneChan   chan any
)

func SendTx(blockData any, nonce [16]byte) error {
	txBytes, err := createTx(blockData, nonce)
	if err != nil {
		return err
	}
	txId, err := submitTx(txBytes)
	if err != nil {
		return err
	}
	slog.Info(
		"successfully submitted TX " + txId,
	)
	return nil
}

func createTx(blockData any, nonce [16]byte) ([]byte, error) {
	cfg := config.GetConfig()
	bursa := wallet.GetWallet()
	store := storage.GetStorage()

	profileCfg := config.GetProfile()

	validatorHash := profileCfg.ValidatorHash
	validatorHashBytes, err := hex.DecodeString(validatorHash)
	if err != nil {
		return nil, err
	}
	mintValidatorHash := profileCfg.MintValidatorHash

	postDatum := PlutusData.PlutusData{
		PlutusDataType: PlutusData.PlutusBytes,
		TagNr:          0,
		Value:          blockData,
	}

	contractAddress, _ := serAddress.DecodeAddress(cfg.Indexer.ScriptAddress)
	myAddress, _ := serAddress.DecodeAddress(bursa.PaymentAddress)
	cc := NewCustomChainContext()
	apollob := apollo.New(&cc)
	apollob, err = apollob.
		SetWalletFromBech32(bursa.PaymentAddress).
		SetWalletAsChangeAddress()
	if err != nil {
		return nil, err
	}

	// Gather input UTxOs from our wallet
	store.Lock()
	utxosBytes, err := store.GetUtxos(bursa.PaymentAddress)
	if err != nil {
		store.Unlock()
		return nil, err
	}
	store.Unlock()
	utxos := []UTxO.UTxO{}
	var tunaPolicyId *Policy.PolicyId
	if profileCfg.UseTunaV1 {
		var err error
		tunaPolicyId, err = Policy.New(validatorHash)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		tunaPolicyId, err = Policy.New(mintValidatorHash)
		if err != nil {
			return nil, err
		}
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
	store.Lock()
	scriptUtxosBytes, err := store.GetUtxos(cfg.Indexer.ScriptAddress)
	if err != nil {
		store.Unlock()
		return nil, err
	}
	store.Unlock()
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
		slog.Warn(
			fmt.Sprintf(
				"found unexpected UTxO(s) at script address (%s), expected 1 and found %d",
				cfg.Indexer.ScriptAddress,
				len(scriptUtxos),
			),
		)
	}
	if len(scriptUtxos) == 0 {
		return nil, errors.New("no script UTxOs found")
	}
	validatorOutRef := scriptUtxos[0]

	var blockDataRealTimeNow int64
	var blockDataBlockNumber int64
	var blockDataHash []byte
	if profileCfg.UseTunaV1 {
		tmpBlockData := blockData.(models.TunaV1State)
		blockDataRealTimeNow = tmpBlockData.RealTimeNow
	} else {
		tmpBlockData := blockData.(models.TunaV2State)
		blockDataRealTimeNow = tmpBlockData.CurrentPosixTime
		blockDataBlockNumber = tmpBlockData.BlockNumber
		blockDataHash = tmpBlockData.CurrentHash
	}

	// Determine validity start/end slot based on datum
	datumSlot := unixTimeToSlot(blockDataRealTimeNow / 1000)

	apollob = apollob.AddLoadedUTxOs(utxos...).
		SetValidityStart(int64(datumSlot - 90)).
		SetTtl(int64(datumSlot + 90)) // #nosec G115

	if profileCfg.UseTunaV1 {
		apollob = apollob.
			PayToAddress(
				myAddress, 2000000, apollo.NewUnit(validatorHash, "TUNA", int(tunaCount+5000000000)),
			).
			PayToContract(
				contractAddress, &postDatum, int(validatorOutRef.Output.PostAlonzo.Amount.Am.Coin), true, apollo.NewUnit(validatorHash, "lord tuna", 1),
			).
			MintAssetsWithRedeemer(
				apollo.NewUnit(validatorHash, "TUNA", 5000000000),
				Redeemer.Redeemer{
					Tag:   Redeemer.MINT,
					Index: 0,
					// NOTE: these values are estimated
					ExUnits: Redeemer.ExecutionUnits{
						Mem:   80_000,
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
	} else {
		// Build miner credential
		userPkh := wallet.PaymentKeyHash()
		minerCredential := cbor.NewConstructor(
			0,
			cbor.IndefLengthList{
				userPkh,
				[]byte(cfg.Miner.Message),
			},
		)
		// Convert old and new block numbers to byte representation for use in token names
		oldBlockNumberBytes := big.NewInt(int64(blockDataBlockNumber - 1)).Bytes()
		newBlockNumberBytes := big.NewInt(int64(blockDataBlockNumber)).Bytes()
		// Temporarily add new target hash to trie to calculate merkle proof
		trie := storage.GetStorage().Trie()
		trie.Lock()
		tmpHashKey := storage.HashValue(blockDataHash).Bytes()
		if err := trie.Update(tmpHashKey, blockDataHash, 0); err != nil {
			trie.Unlock()
			return nil, err
		}
		proof, err := trie.Prove(tmpHashKey)
		if err != nil {
			trie.Unlock()
			return nil, err
		}
		// Remove item from trie until it comes in via the indexer
		_ = trie.Delete(tmpHashKey)
		trie.Unlock()
		minerRedeemer := Redeemer.Redeemer{
			Tag: Redeemer.SPEND,
			// NOTE: these values are estimated
			ExUnits: Redeemer.ExecutionUnits{
				Mem:   1_500_000,
				Steps: 550_000_000,
			},
			Data: PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				TagNr:          0,
				Value: cbor.NewConstructor(
					0,
					cbor.IndefLengthList{
						nonce,
						minerCredential,
						proof,
					},
				),
			},
		}
		mintRedeemer := Redeemer.Redeemer{
			Tag: Redeemer.MINT,
			// NOTE: these values are estimated
			ExUnits: Redeemer.ExecutionUnits{
				Mem:   280_000,
				Steps: 130_000_000,
			},
			Data: PlutusData.PlutusData{
				PlutusDataType: PlutusData.PlutusBytes,
				TagNr:          0,
				Value: cbor.NewConstructor(
					1,
					cbor.IndefLengthList{
						cbor.NewConstructor(
							0,
							cbor.IndefLengthList{
								cbor.NewConstructor(
									0,
									cbor.IndefLengthList{
										validatorOutRef.Input.TransactionId,
									},
								),
								validatorOutRef.Input.Index,
							},
						),
						blockDataBlockNumber - 1,
					},
				),
			},
		}
		apollob = apollob.
			PayToAddress(
				myAddress, 2000000, apollo.NewUnit(mintValidatorHash, "TUNA", int(tunaCount+5000000000)),
			).
			PayToContract(
				contractAddress,
				&postDatum,
				int(validatorOutRef.Output.PostAlonzo.Amount.Am.Coin),
				true,
				apollo.NewUnit(mintValidatorHash, "TUNA"+string(validatorHashBytes), 1),
				apollo.NewUnit(mintValidatorHash, "COUNTER"+string(newBlockNumberBytes), 1),
			).
			CollectFrom(
				validatorOutRef,
				minerRedeemer,
			).
			MintAssetsWithRedeemer(
				apollo.NewUnit(mintValidatorHash, "TUNA", 5000000000),
				mintRedeemer,
			).
			MintAssetsWithRedeemer(
				apollo.NewUnit(mintValidatorHash, "COUNTER"+string(newBlockNumberBytes), 1),
				mintRedeemer,
			).
			MintAssetsWithRedeemer(
				apollo.NewUnit(mintValidatorHash, "COUNTER"+string(oldBlockNumberBytes), -1),
				mintRedeemer,
			).
			AddRequiredSigner(
				serialization.PubKeyHash(userPkh),
			)
	}
	if len(profileCfg.ScriptRefInputs) > 0 {
		// Use script reference input(s)
		for _, refInput := range profileCfg.ScriptRefInputs {
			apollob = apollob.AddReferenceInput(
				refInput.TxId,
				int(refInput.OutputIdx),
			)
		}
	} else {
		// Include the script with the TX
		validatorScriptBytes, err := hex.DecodeString(profileCfg.ValidatorScript)
		if err != nil {
			return nil, err
		}
		apollob = apollob.AttachV2Script(PlutusData.PlutusV2Script(validatorScriptBytes))
	}

	// Disable ExUnits estimation, since it doesn't work with the backend we use
	apollob = apollob.DisableExecutionUnitsEstimation()

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
	skey := Key.SigningKey{Payload: sKeyBytes}
	tx, err = tx.SignWithSkey(vkey, skey)
	if err != nil {
		return nil, err
	}
	txBytes, err := tx.GetTx().Bytes()
	if err != nil {
		return nil, err
	}
	slog.Debug(
		fmt.Sprintf("TX bytes: %x", txBytes),
	)
	return txBytes, nil
}

func unixTimeToSlot(unixTime int64) uint64 {
	cfg := config.GetConfig()
	networkCfg := config.Networks[cfg.Network]
	if unixTime < 0 {
		panic("you have traveled backward in time")
	}
	// #nosec G115
	return networkCfg.ShelleyOffsetSlot + uint64(
		unixTime-networkCfg.ShelleyOffsetTime,
	)
}

func submitTx(txRawBytes []byte) (string, error) {
	cfg := config.GetConfig()
	if cfg.Submit.Address != "" {
		return submitTxNtN(txRawBytes)
	} else if cfg.Submit.SocketPath != "" {
		return submitTxNtC(txRawBytes)
	} else if cfg.Submit.Url != "" {
		return submitTxApi(txRawBytes)
	} else {
		// Populate address info from indexer network
		network, ok := ouroboros.NetworkByName(cfg.Network)
		if !ok {
			slog.Error(
				"unknown network: " + cfg.Network,
			)
			os.Exit(1)
		}
		if len(network.BootstrapPeers) == 0 {
			slog.Error(
				"no known peers for network: " + cfg.Network,
			)
			os.Exit(1)
		}
		peer := network.BootstrapPeers[0]
		cfg.Submit.Address = fmt.Sprintf("%s:%d", peer.Address, peer.Port)
		return submitTxNtN(txRawBytes)
	}
}

func submitTxNtN(txRawBytes []byte) (string, error) {
	ntnMutex.Lock()
	defer ntnMutex.Unlock()
	cfg := config.GetConfig()

	// Record TX bytes in global for use in handler functions
	ntnTxBytes = txRawBytes[:]
	ntnSentTx = false

	// Generate TX hash
	// Unwrap raw transaction bytes into a CBOR array
	txUnwrap := []cbor.RawMessage{}
	if _, err := cbor.Decode(txRawBytes, &txUnwrap); err != nil {
		slog.Error(
			fmt.Sprintf("failed to unwrap transaction CBOR: %s", err),
		)
		return "", fmt.Errorf("failed to unwrap transaction CBOR: %w", err)
	}
	// index 0 is the transaction body
	// Store index 0 (transaction body) as byte array
	txBody := txUnwrap[0]
	// Convert the body into a blake2b256 hash string
	ntnTxHash = blake2b.Sum256(txBody)

	// Create connection
	conn, err := createClientConnection(cfg.Submit.Address)
	if err != nil {
		return "", err
	}
	o, err := ouroboros.New(
		ouroboros.WithConnection(conn),
		ouroboros.WithNetworkMagic(cfg.NetworkMagic),
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
	// Capture errors
	doneChan = make(chan any)
	go func() {
		err, ok := <-o.ErrorChan()
		if ok {
			select {
			case <-doneChan:
				return
			default:
			}
			close(doneChan)
			slog.Error(
				fmt.Sprintf("async error submitting TX via NtN: %s", err),
			)
		}
	}()
	// Start txSubmission loop
	o.TxSubmission().Client.Init()
	<-doneChan
	// Sleep 1s to allow time for TX to enter remote mempool before closing connection
	time.Sleep(1 * time.Second)

	if err := o.Close(); err != nil {
		return "", fmt.Errorf("failed to close connection: %w", err)
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
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.Submit.Url,
		reqBody,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/cbor")
	if cfg.Submit.BlockFrostProjectID != "" {
		req.Header.Add("project_id", cfg.Submit.BlockFrostProjectID)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf(
			"failed to send request: %s: %w",
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
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return string(respBody), nil
	} else {
		return "", fmt.Errorf("failed to submit TX to API: %s: %d: %s", cfg.Submit.Url, resp.StatusCode, respBody)
	}
}

func createClientConnection(nodeAddress string) (net.Conn, error) {
	var err error
	var conn net.Conn
	var dialProto string
	var dialAddress string
	dialProto = "tcp"
	dialAddress = nodeAddress

	conn, err = net.Dial(dialProto, dialAddress)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	return conn, nil
}

func handleRequestTxIds(
	ctx txsubmission.CallbackContext,
	blocking bool,
	ack uint16,
	req uint16,
) ([]txsubmission.TxIdAndSize, error) {
	// Shutdown if we've already sent the TX
	if ntnSentTx {
		select {
		case <-doneChan:
			return nil, nil
		default:
		}
		close(doneChan)
		// This prevents creating an async error while waiting for shutdown
		time.Sleep(2 * time.Second)
		return nil, nil
	}
	ret := []txsubmission.TxIdAndSize{
		{
			TxId: txsubmission.TxId{
				EraId: 5,
				TxId:  ntnTxHash,
			},
			Size: uint32(len(ntnTxBytes)), // #nosec G115
		},
	}
	return ret, nil
}

func handleRequestTxs(
	ctx txsubmission.CallbackContext,
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
