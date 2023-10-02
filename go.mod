module github.com/blinklabs-io/bluefin

go 1.20

require (
	github.com/Salvionied/apollo v1.0.4
	github.com/Salvionied/cbor/v2 v2.6.0
	github.com/blinklabs-io/bursa v0.4.0
	github.com/blinklabs-io/gouroboros v0.53.0
	github.com/blinklabs-io/snek v0.12.1
	github.com/dgraph-io/badger/v4 v4.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/minio/sha256-simd v1.0.1
	go.uber.org/automaxprocs v1.5.3
	go.uber.org/zap v1.26.0
	golang.org/x/crypto v0.13.0
	gopkg.in/yaml.v2 v2.4.0
)

// XXX: uncomment when testing local changes to bursa
// replace github.com/blinklabs-io/bursa => ../bursa

// XXX: uncomment when testing local changes to gouroboros
// replace github.com/blinklabs-io/gouroboros => ../gouroboros

// XXX: uncomment when testing local changes to snek
// replace github.com/blinklabs-io/snek => ../snek

require (
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/fivebinaries/go-cardano-serialization v0.0.0-20220907134105-ec9b85086588 // indirect
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/flatbuffers v1.12.1 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/klauspost/compress v1.12.3 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opencensus.io v0.22.5 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
