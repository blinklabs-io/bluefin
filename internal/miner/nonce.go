package miner

import "crypto/rand"

func GenerateNonce() []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return nonce
}

// IncrementNonce increments the given nonce.
func IncrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		if nonce[i] < 255 {
			nonce[i]++
			break
		}
		nonce[i] = 0
	}
}
