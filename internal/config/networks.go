package config

type Network struct {
	ShelleyOffsetSlot uint64
	ShelleyOffsetTime int64
}

var Networks = map[string]Network{
	"preview": Network{
		ShelleyOffsetSlot: 0,
		ShelleyOffsetTime: 1666656000,
	},
	"mainnet": Network{
		ShelleyOffsetSlot: 4924800,
		ShelleyOffsetTime: 1596491091,
	},
}
