module github.com/blinklabs-io/bluefin

go 1.22

toolchain go1.22.8

require (
	github.com/Salvionied/apollo v1.0.13-0.20240908221422-e50b26fff03e
	github.com/blinklabs-io/adder v0.25.2
	github.com/blinklabs-io/bursa v0.8.3
	github.com/blinklabs-io/cardano-models v0.4.0
	github.com/blinklabs-io/gouroboros v0.106.2
	github.com/blinklabs-io/merkle-patricia-forestry v0.1.1
	github.com/dgraph-io/badger/v4 v4.5.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/minio/sha256-simd v1.0.1
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.32.0
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
	github.com/Salvionied/cbor/v2 v2.6.0 // indirect
	github.com/SundaeSwap-finance/kugo v1.0.5 // indirect
	github.com/SundaeSwap-finance/ogmigo/v6 v6.0.0-20240117201106-ce491d0b031e // indirect
	github.com/aws/aws-sdk-go v1.48.7 // indirect
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.0.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fivebinaries/go-cardano-serialization v0.0.0-20220907134105-ec9b85086588 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.5 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.23.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/google/flatbuffers v24.3.25+incompatible // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/maestro-org/go-sdk v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	github.com/utxorpc/go-codegen v0.15.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/exp v0.0.0-20240404231335-c0f41cb1a7a0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/protobuf v1.36.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
