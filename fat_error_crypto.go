package sphinx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

var byteOrder = binary.BigEndian

type FatErrorStructure struct {
	MaxHops        int
	MaxPayloadSize int
}

type fatErrorBase struct {
	maxHops             int
	totalHmacs          int
	allHmacsLen         int
	hmacsAndPayloadsLen int
	allPayloadsLen      int
	payloadLen          int
	payloadDataLen      int
}

func newFatErrorBase(structure *FatErrorStructure) fatErrorBase {
	var (
		payloadDataLen = structure.MaxPayloadSize

		// payloadLen is the size of the per-node payload. It consists of a 1-byte
		// payload type followed by the payload data.
		payloadLen = 1 + payloadDataLen

		totalHmacs          = (structure.MaxHops * (structure.MaxHops + 1)) / 2
		allHmacsLen         = totalHmacs * sha256.Size
		allPayloadsLen      = payloadLen * structure.MaxHops
		hmacsAndPayloadsLen = allHmacsLen + allPayloadsLen
	)

	return fatErrorBase{
		totalHmacs:          totalHmacs,
		allHmacsLen:         allHmacsLen,
		hmacsAndPayloadsLen: hmacsAndPayloadsLen,
		allPayloadsLen:      allPayloadsLen,
		maxHops:             structure.MaxHops,
		payloadLen:          payloadLen,
		payloadDataLen:      payloadDataLen,
	}
}

// getMsgComponents splits a complete failure message into its components
// without re-allocating memory.
func (o *fatErrorBase) getMsgComponents(data []byte) ([]byte, []byte, []byte) {
	payloads := data[len(data)-o.hmacsAndPayloadsLen : len(data)-o.allHmacsLen]
	hmacs := data[len(data)-o.allHmacsLen:]
	message := data[:len(data)-o.hmacsAndPayloadsLen]

	return message, payloads, hmacs
}

// calculateHmac calculates an hmac given a shared secret and a presumed
// position in the path. Position is expressed as the distance to the error
// source. The error source itself is at position 0.
func (o *fatErrorBase) calculateHmac(sharedSecret Hash256, position int,
	message, payloads, hmacs []byte) []byte {

	umKey := generateKey("um", &sharedSecret)
	hash := hmac.New(sha256.New, umKey[:])

	// Include message.
	_, _ = hash.Write(message)

	// Include payloads including our own.
	_, _ = hash.Write(payloads[:(o.maxHops-position)*o.payloadLen])

	// Include downstream hmacs.
	var hmacsIdx = position + o.maxHops
	for j := 0; j < o.maxHops-position-1; j++ {
		_, _ = hash.Write(
			hmacs[hmacsIdx*sha256.Size : (hmacsIdx+1)*sha256.Size],
		)

		hmacsIdx += o.maxHops - j - 1
	}

	return hash.Sum(nil)
}
