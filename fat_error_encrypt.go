package sphinx

import (
	"crypto/sha256"
	"fmt"
)

// NewOnionFatErrorEncrypter creates new instance of the onion encrypter backed
// by the passed shared secret.
func NewOnionFatErrorEncrypter(sharedSecret Hash256,
	structure *FatErrorStructure) *OnionFatErrorEncrypter {

	return &OnionFatErrorEncrypter{
		fatErrorBase: newFatErrorBase(structure),

		sharedSecret: sharedSecret,
	}
}

// OnionFatErrorEncrypter is a struct that's used to implement fat onion error
// encryption as defined within BOLT0004.
type OnionFatErrorEncrypter struct {
	fatErrorBase

	sharedSecret Hash256
}

func (o *OnionFatErrorEncrypter) shiftHmacsRight(hmacs []byte) {
	if len(hmacs) != o.allHmacsLen {
		panic("invalid hmac block length")
	}

	srcIdx := o.totalHmacs - 2
	destIdx := o.totalHmacs - 1
	copyLen := 1
	for i := 0; i < o.maxHops-1; i++ {
		copy(
			hmacs[destIdx*sha256.Size:],
			hmacs[srcIdx*sha256.Size:(srcIdx+copyLen)*sha256.Size],
		)

		copyLen++

		srcIdx -= copyLen + 1
		destIdx -= copyLen
	}
}

func (o *OnionFatErrorEncrypter) shiftPayloadsRight(payloads []byte) {
	if len(payloads) != o.allPayloadsLen {
		panic("invalid payload block length")
	}

	copy(payloads[o.payloadLen:], payloads)
}

// addHmacs updates the failure data with a series of hmacs corresponding to all
// possible positions in the path for the current node.
func (o *OnionFatErrorEncrypter) addHmacs(data []byte) {
	message, payloads, hmacs := o.getMsgComponents(data)

	for i := 0; i < o.maxHops; i++ {
		hmac := o.calculateHmac(o.sharedSecret, i, message, payloads, hmacs)

		copy(hmacs[i*sha256.Size:], hmac)
	}
}

// EncryptError is used to make data obfuscation using the generated shared
// secret.
//
// In context of Lightning Network is either used by the nodes in order to make
// initial obfuscation with the creation of the hmac or by the forwarding nodes
// for backward failure obfuscation of the onion failure blob. By obfuscating
// the onion failure on every node in the path we are adding additional step of
// the security and barrier for malware nodes to retrieve valuable information.
// The reason for using onion obfuscation is to not give
// away to the nodes in the payment path the information about the exact
// failure and its origin.
func (o *OnionFatErrorEncrypter) EncryptError(initial bool, data []byte,
	payload []byte) ([]byte, error) {

	if initial {
		if len(data) < minOnionErrorLength {
			return nil, fmt.Errorf(
				"initial data size less than %v",
				minOnionErrorLength,
			)
		}

		data = o.initializePayload(data, payload)
	} else {
		if len(data) < minOnionErrorLength+o.hmacsAndPayloadsLen {
			return nil, fmt.Errorf(
				"data size less than %v",
				minOnionErrorLength+o.hmacsAndPayloadsLen,
			)
		}

		o.addIntermediatePayload(data, payload)
	}

	// Update hmac block.
	o.addHmacs(data)

	// Obfuscate.
	return onionEncrypt(&o.sharedSecret, data), nil
}

func (o *OnionFatErrorEncrypter) initializePayload(message []byte,
	payload []byte) []byte {

	// Add space for payloads and hmacs.
	data := make([]byte, len(message)+o.hmacsAndPayloadsLen)
	copy(data, message)

	_, payloads, _ := o.getMsgComponents(data)

	// Signal final hops in the payload.
	addPayload(payloads, payloadFinal, payload)

	return data
}

func (o *OnionFatErrorEncrypter) addIntermediatePayload(data []byte,
	payload []byte) {

	_, payloads, hmacs := o.getMsgComponents(data)

	// Shift hmacs and payloads to create space for the payload.
	o.shiftPayloadsRight(payloads)
	o.shiftHmacsRight(hmacs)

	// Signal intermediate hop in the payload.
	addPayload(payloads, payloadIntermediate, payload)
}

func addPayload(payloads []byte, payloadType PayloadType, payload []byte) {
	payloads[0] = byte(payloadType)
	copy(payloads[1:], payload)
}
