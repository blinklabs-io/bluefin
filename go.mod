module github.com/blinklabs-io/bluefin

go 1.24.0

toolchain go1.24.4

require (
	github.com/Salvionied/apollo v1.5.0
	github.com/blinklabs-io/adder v0.35.0
	github.com/blinklabs-io/bursa v0.14.0
	github.com/blinklabs-io/cardano-models v0.7.0
	github.com/blinklabs-io/gouroboros v0.152.2
	github.com/blinklabs-io/merkle-patricia-forestry v0.1.6
	github.com/dgraph-io/badger/v4 v4.9.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/minio/sha256-simd v1.0.1
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.47.0
	gopkg.in/yaml.v2 v2.4.0
)

// XXX: uncomment when testing local changes to bursa
// replace github.com/blinklabs-io/bursa => ../bursa

// XXX: uncomment when testing local changes to gouroboros
// replace github.com/blinklabs-io/gouroboros => ../gouroboros

// XXX: uncomment when testing local changes to adder
// replace github.com/blinklabs-io/adder => ../adder

// XXX: uncomment when testing local changes to cardano-models
// replace github.com/blinklabs-io/cardano-models => ../cardano-models

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/SundaeSwap-finance/kugo v1.3.0 // indirect
	github.com/SundaeSwap-finance/ogmigo/v6 v6.2.0 // indirect
	github.com/aws/aws-sdk-go v1.55.6 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/blinklabs-io/plutigo v0.0.22 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.6 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/gnark-crypto v0.19.2 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ethereum/go-ethereum v1.16.8 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/maestro-org/go-sdk v1.2.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	github.com/utxorpc/go-codegen v0.18.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
