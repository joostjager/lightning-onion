package sphinx

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// DecryptedFatError contains the decrypted fat error message and its sender.
type DecryptedFatError struct {
	DecryptedError

	// Payloads is an array of data blocks reported by each node on the (error)
	// path.
	Payloads [][]byte
}

// OnionFatErrorDecrypter is a struct that's used to decrypt fat onion errors in
// response to failed HTLC routing attempts according to BOLT#4.
type OnionFatErrorDecrypter struct {
	fatErrorBase

	circuit *Circuit
}

// NewOnionFatErrorDecrypter creates new instance of a fat error onion
// decrypter.
func NewOnionFatErrorDecrypter(circuit *Circuit,
	structure *FatErrorStructure) *OnionFatErrorDecrypter {

	return &OnionFatErrorDecrypter{
		fatErrorBase: newFatErrorBase(structure),
		circuit:      circuit,
	}
}

// DecryptError attempts to decrypt the passed encrypted error response. The
// onion failure is encrypted in backward manner, starting from the node where
// error have occurred. As a result, in order to decrypt the error we need get
// all shared secret and apply decryption in the reverse order. A structure is
// returned that contains the decrypted error message and information on the
// sender.
func (o *OnionFatErrorDecrypter) DecryptError(encryptedData []byte) (
	*DecryptedFatError, error) {

	// Ensure the error message length is enough to contain the payloads and
	// hmacs blocks. Otherwise blame the first hop.
	if len(encryptedData) < minOnionErrorLength+o.hmacsAndPayloadsLen {
		return &DecryptedFatError{
			DecryptedError: DecryptedError{
				SenderIdx: 1,
				Sender:    o.circuit.PaymentPath[0],
			},
		}, nil
	}

	sharedSecrets, err := generateSharedSecrets(
		o.circuit.PaymentPath,
		o.circuit.SessionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %w", err)
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
	hopPayloads := make([][]byte, 0)
	for i := 0; i < o.maxHops; i++ {
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

		message, payloads, hmacs := o.getMsgComponents(encryptedData)

		expectedHmac := o.calculateHmac(
			sharedSecret, i, message, payloads, hmacs,
		)
		actualHmac := hmacs[i*sha256.Size : (i+1)*sha256.Size]

		// If the hmac does not match up, exit with a nil message.
		if !bytes.Equal(actualHmac, expectedHmac) && sender == 0 {
			sender = i + 1
			msg = nil
		}

		// Extract the payload and exit with a nil message if it is invalid.
		payloadType, payload, err := o.extractPayload(payloads)
		if sender == 0 {
			if err != nil {
				sender = i + 1
				msg = nil
			}

			// Store data reported by this node.
			hopPayloads = append(hopPayloads, payload)

			// If we are at the node that is the source of the error, we can now
			// save the message in our return variable.
			if payloadType == payloadFinal {
				sender = i + 1
				msg = message
			}
		}

		// Shift payloads and hmacs to the left to prepare for the next
		// iteration.
		o.shiftPayloadsLeft(payloads)
		o.shiftHmacsLeft(hmacs)
	}

	// If the sender index is still zero, all hmacs checked out but none of the
	// payloads was a final payload. In this case we must be dealing with a max
	// length route and a final hop that returned an intermediate payload. Blame
	// the final hop.
	if sender == 0 {
		sender = o.maxHops
		msg = nil
	}

	return &DecryptedFatError{
		DecryptedError: DecryptedError{
			SenderIdx: sender,
			Sender:    o.circuit.PaymentPath[sender-1],
			Message:   msg,
		},
		Payloads: hopPayloads,
	}, nil
}

const (
	payloadFinal        = 1
	payloadIntermediate = 0
)

func (o *OnionFatErrorDecrypter) shiftHmacsLeft(hmacs []byte) {
	if len(hmacs) != o.allHmacsLen {
		panic("invalid hmac block length")
	}

	srcIdx := o.maxHops
	destIdx := 1
	copyLen := o.maxHops - 1
	for i := 0; i < o.maxHops-1; i++ {
		copy(
			hmacs[destIdx*sha256.Size:],
			hmacs[srcIdx*sha256.Size:(srcIdx+copyLen)*sha256.Size],
		)

		srcIdx += copyLen
		destIdx += copyLen + 1
		copyLen--
	}
}

func (o *OnionFatErrorDecrypter) shiftPayloadsLeft(payloads []byte) {
	if len(payloads) != o.allPayloadsLen {
		panic("invalid payload block length")
	}

	copy(payloads, payloads[o.payloadLen:o.maxHops*o.payloadLen])
}

func (o *OnionFatErrorDecrypter) extractPayload(payloads []byte) (PayloadType,
	[]byte, error) {

	var payloadType PayloadType

	switch payloads[0] {
	case payloadFinal, payloadIntermediate:
		payloadType = PayloadType(payloads[0])

	default:
		return 0, nil, errors.New("invalid payload type")
	}

	payload := make([]byte, o.payloadDataLen)
	copy(payload, payloads[1:o.payloadLen])

	return payloadType, payload, nil
}
