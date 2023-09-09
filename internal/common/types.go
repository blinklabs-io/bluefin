package common

type BlockData struct {
	BlockNumber      int64
	TargetHash       []byte
	LeadingZeros     int64
	DifficultyNumber int64
	EpochTime        int64
	RealTimeNow      int64
	Message          []byte
	Interlink        [][]byte
}
