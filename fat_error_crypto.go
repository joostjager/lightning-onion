package sphinx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

var byteOrder = binary.BigEndian

// DecryptError attempts to decrypt the passed encrypted error response. The
// onion failure is encrypted in backward manner, starting from the node where
// error have occurred. As a result, in order to decrypt the error we need get
// all shared secret and apply decryption in the reverse order. A structure is
// returned that contains the decrypted error message and information on the
// sender.
func (o *OnionErrorDecrypter) DecryptFatError(encryptedData []byte) (
	*DecryptedError, error) {

	// Ensure the error message length is enough to contain the payloads and
	// hmacs blocks.
	if len(encryptedData) < hmacsAndPayloadsLen {
		return nil, fmt.Errorf("invalid error length: "+
			"expected at least %v got %v", hmacsAndPayloadsLen,
			len(encryptedData))
	}

	sharedSecrets, err := generateSharedSecrets(
		o.circuit.PaymentPath,
		o.circuit.SessionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v",
			err)
	}

	var (
		sender      int
		msg         []byte
		dummySecret Hash256
	)
	copy(dummySecret[:], bytes.Repeat([]byte{1}, 32))

	// We'll iterate a constant amount of hops to ensure that we don't give
	// away an timing information pertaining to the position in the route
	// that the error emanated from.
	holdTimesMs := make([]uint64, 0)
	for i := 0; i < NumMaxHops; i++ {
		var sharedSecret Hash256

		// If we've already found the sender, then we'll use our dummy
		// secret to continue decryption attempts to fill out the rest
		// of the loop. Otherwise, we'll use the next shared secret in
		// line.
		if sender != 0 || i > len(sharedSecrets)-1 {
			sharedSecret = dummySecret
		} else {
			sharedSecret = sharedSecrets[i]
		}

		// With the shared secret, we'll now strip off a layer of
		// encryption from the encrypted error payload.
		encryptedData = onionEncrypt(&sharedSecret, encryptedData)

		message, payloads, hmacs := getMsgComponents(encryptedData)

		expectedHmac := calculateHmac(sharedSecret, i, message, payloads, hmacs)
		actualHmac := hmacs[i*sha256.Size : (i+1)*sha256.Size]

		// If the hmac does not match up, exit with a nil message.
		if !bytes.Equal(actualHmac, expectedHmac[:]) && sender == 0 {
			sender = i + 1
			msg = nil
		}

		// Extract the payload and exit with a nil message if it is invalid.
		payloadType, holdTimeMs, err := extractPayload(payloads)
		if sender == 0 {
			if err != nil {
				sender = i + 1
				msg = nil
			}

			// Store hold time reported by this node.
			holdTimesMs = append(holdTimesMs, holdTimeMs)

			// If we are at the node that is the source of the error, we can now
			// save the message in our return variable.
			if payloadType == payloadFinal {
				sender = i + 1
				msg = message
			}
		}

		// Shift payloads and hmacs to the left to prepare for the next
		// iteration.
		shiftPayloadsLeft(payloads)
		shiftHmacsLeft(hmacs)
	}

	// If the sender index is still zero, all hmacs checked out but none of the
	// payloads was a final payload. In this case we must be dealing with a max
	// length route and a final hop that returned an intermediate payload. Blame
	// the final hop.
	if sender == 0 {
		sender = NumMaxHops
		msg = nil
	}

	return &DecryptedError{
		SenderIdx:   sender,
		Sender:      o.circuit.PaymentPath[sender-1],
		Message:     msg,
		HoldTimesMs: holdTimesMs,
	}, nil
}

const (
	totalHmacs          = (NumMaxHops * (NumMaxHops + 1)) / 2
	allHmacsLen         = totalHmacs * sha256.Size
	hmacsAndPayloadsLen = allHmacsLen + allPayloadsLen

	// payloadLen is the size of the per-node payload. It consists of a 1-byte
	// payload type and an 8-byte hold time.
	payloadLen = 1 + 8

	allPayloadsLen = payloadLen * NumMaxHops

	payloadFinal        = 1
	payloadIntermediate = 0
)

func shiftHmacsRight(hmacs []byte) {
	if len(hmacs) != allHmacsLen {
		panic("invalid hmac block length")
	}

	srcIdx := totalHmacs - 2
	destIdx := totalHmacs - 1
	copyLen := 1
	for i := 0; i < NumMaxHops-1; i++ {
		copy(hmacs[destIdx*sha256.Size:], hmacs[srcIdx*sha256.Size:(srcIdx+copyLen)*sha256.Size])

		copyLen++

		srcIdx -= copyLen + 1
		destIdx -= copyLen
	}
}

func shiftHmacsLeft(hmacs []byte) {
	if len(hmacs) != allHmacsLen {
		panic("invalid hmac block length")
	}

	srcIdx := NumMaxHops
	destIdx := 1
	copyLen := NumMaxHops - 1
	for i := 0; i < NumMaxHops-1; i++ {
		copy(hmacs[destIdx*sha256.Size:], hmacs[srcIdx*sha256.Size:(srcIdx+copyLen)*sha256.Size])

		srcIdx += copyLen
		destIdx += copyLen + 1
		copyLen--
	}
}

func shiftPayloadsRight(payloads []byte) {
	if len(payloads) != allPayloadsLen {
		panic("invalid payload block length")
	}

	copy(payloads[payloadLen:], payloads)
}

func shiftPayloadsLeft(payloads []byte) {
	if len(payloads) != allPayloadsLen {
		panic("invalid payload block length")
	}

	copy(payloads, payloads[payloadLen:NumMaxHops*payloadLen])
}

// getMsgComponents splits a complete failure message into its components
// without re-allocating memory.
func getMsgComponents(data []byte) ([]byte, []byte, []byte) {
	payloads := data[len(data)-hmacsAndPayloadsLen : len(data)-allHmacsLen]
	hmacs := data[len(data)-allHmacsLen:]
	message := data[:len(data)-hmacsAndPayloadsLen]

	return message, payloads, hmacs
}

// calculateHmac calculates an hmac given a shared secret and a presumed
// position in the path. Position is expressed as the distance to the error
// source. The error source itself is at position 0.
func calculateHmac(sharedSecret Hash256, position int,
	message, payloads, hmacs []byte) []byte {

	umKey := generateKey("um", &sharedSecret)
	hash := hmac.New(sha256.New, umKey[:])

	// Include payloads including our own.
	_, _ = hash.Write(payloads[:(NumMaxHops-position)*payloadLen])

	// Include downstream hmacs.
	var downstreamHmacsIdx = position + NumMaxHops
	for j := 0; j < NumMaxHops-position-1; j++ {
		_, _ = hash.Write(hmacs[downstreamHmacsIdx*sha256.Size : (downstreamHmacsIdx+1)*sha256.Size])

		downstreamHmacsIdx += NumMaxHops - j - 1
	}

	// Include message.
	_, _ = hash.Write(message)

	return hash.Sum(nil)
}

// calculateHmac calculates an hmac using the shared secret for this
// OnionErrorEncryptor instance.
func (o *OnionErrorEncrypter) calculateHmac(position int,
	message, payloads, hmacs []byte) []byte {

	return calculateHmac(o.sharedSecret, position, message, payloads, hmacs)
}

// addHmacs updates the failure data with a series of hmacs corresponding to all
// possible positions in the path for the current node.
func (o *OnionErrorEncrypter) addHmacs(data []byte) {
	message, payloads, hmacs := getMsgComponents(data)

	for i := 0; i < NumMaxHops; i++ {
		hmac := o.calculateHmac(i, message, payloads, hmacs)

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
func (o *OnionErrorEncrypter) EncryptFatError(initial bool, data []byte,
	holdTimeMs uint64) []byte {

	if initial {
		data = o.initializePayload(data, holdTimeMs)
	} else {
		o.addIntermediatePayload(data, holdTimeMs)
	}

	// Update hmac block.
	o.addHmacs(data)

	// Obfuscate.
	return onionEncrypt(&o.sharedSecret, data)
}

func (o *OnionErrorEncrypter) initializePayload(message []byte,
	holdTimeMs uint64) []byte {

	// Add space for payloads and hmacs.
	data := make([]byte, len(message)+hmacsAndPayloadsLen)
	copy(data, message)

	_, payloads, _ := getMsgComponents(data)

	// Signal final hops in the payload.
	addPayload(payloads, payloadFinal, holdTimeMs)

	return data
}

func addPayload(payloads []byte, payloadType PayloadType, holdTimeMs uint64) {
	byteOrder.PutUint64(payloads[1:], uint64(holdTimeMs))

	payloads[0] = byte(payloadType)
}

func extractPayload(payloads []byte) (PayloadType, uint64, error) {
	var payloadType PayloadType

	switch payloads[0] {
	case payloadFinal, payloadIntermediate:
		payloadType = PayloadType(payloads[0])

	default:
		return 0, 0, errors.New("invalid payload type")
	}

	holdTimeMs := byteOrder.Uint64(payloads[1:])

	return payloadType, holdTimeMs, nil
}

func (o *OnionErrorEncrypter) addIntermediatePayload(data []byte,
	holdTimeMs uint64) {

	_, payloads, hmacs := getMsgComponents(data)

	// Shift hmacs and payloads to create space for the payload.
	shiftPayloadsRight(payloads)
	shiftHmacsRight(hmacs)

	// Signal intermediate hop in the payload.
	addPayload(payloads, payloadIntermediate, holdTimeMs)
}
