module github.com/blinklabs-io/bluefin

go 1.19

require (
	github.com/blinklabs-io/bursa v0.2.0
	github.com/blinklabs-io/gouroboros v0.52.0
	github.com/blinklabs-io/snek v0.7.0
	github.com/kelseyhightower/envconfig v1.4.0
	go.uber.org/zap v1.25.0
	gopkg.in/yaml.v2 v2.4.0
)

// XXX: uncomment when testing local changes to bursa
// replace github.com/blinklabs-io/bursa v0.2.0 => ../bursa

// XXX: uncomment when testing local changes to gouroboros
// replace github.com/blinklabs-io/gouroboros v0.52.0 => ../gouroboros

require (
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/fivebinaries/go-cardano-serialization v0.0.0-20220907134105-ec9b85086588 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
)
