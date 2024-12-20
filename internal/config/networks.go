package config

type Network struct {
	ShelleyOffsetSlot uint64
	ShelleyOffsetTime int64
}

var Networks = map[string]Network{
	"preview": {
		ShelleyOffsetSlot: 0,
		ShelleyOffsetTime: 1666656000,
	},
	"mainnet": {
		ShelleyOffsetSlot: 4924800,
		ShelleyOffsetTime: 1596491091,
	},
}
