package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var fatErrorTestStructure = &FatErrorStructure{
	MaxHops:        27,
	MaxPayloadSize: 8,
}

// TestFatOnionFailure checks the ability of sender of payment to decode the
// obfuscated onion error.
func TestFatOnionFailure(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := NewOnionFatErrorEncrypter(
		sharedSecrets[len(errorPath)-1], fatErrorTestStructure,
	)

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	finalPayload := [8]byte{1}
	obfuscatedData, err := obfuscator.EncryptError(
		true, failureData, finalPayload[:],
	)
	require.NoError(t, err)
	payloads := [][]byte{finalPayload[:]}

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = NewOnionFatErrorEncrypter(
			sharedSecrets[i], fatErrorTestStructure,
		)

		intermediatePayload := [8]byte{byte(100 + i)}
		obfuscatedData, err = obfuscator.EncryptError(
			false, obfuscatedData, intermediatePayload[:],
		)
		require.NoError(t, err)

		payloads = append([][]byte{intermediatePayload[:]}, payloads...)
	}

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionFatErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, fatErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// We should understand the node from which error have been received.
	require.Equal(t,
		errorPath[len(errorPath)-1].SerializeCompressed(),
		decryptedError.Sender.SerializeCompressed())

	require.Equal(t, len(errorPath), decryptedError.SenderIdx)

	// Check that message have been properly de-obfuscated.
	require.Equal(t, failureData, decryptedError.Message)
	require.Equal(t, payloads, decryptedError.Payloads)
}

// TestOnionFailureCorruption checks the ability of sender of payment to
// identify a node on the path that corrupted the failure message.
func TestOnionFailureCorruption(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := NewOnionFatErrorEncrypter(
		sharedSecrets[len(errorPath)-1], fatErrorTestStructure,
	)

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	payload := [8]byte{1}
	obfuscatedData, err := obfuscator.EncryptError(true, failureData, payload[:])
	require.NoError(t, err)

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = NewOnionFatErrorEncrypter(
			sharedSecrets[i], fatErrorTestStructure,
		)

		payload := [8]byte{byte(100 + i)}
		obfuscatedData, err = obfuscator.EncryptError(
			false, obfuscatedData, payload[:],
		)
		require.NoError(t, err)

		// Hop 1 (the second hop from the sender pov) is corrupting the failure
		// message.
		if i == 1 {
			obfuscatedData[0] ^= 255
		}
	}

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionFatErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, fatErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// Assert that the second hop is correctly identified as the error source.
	require.Equal(t, 2, decryptedError.SenderIdx)
	require.Nil(t, decryptedError.Message)
}

type specHop struct {
	SharedSecret     string `json:"sharedSecret"`
	EncryptedMessage string `json:"encryptedMessage"`
}

type specVector struct {
	EncodedFailureMessage string `json:"encodedFailureMessage"`

	Hops []specHop `json:"hops"`
}

// TestOnionFailureSpecVector checks that onion error corresponds to the
// specification.
func TestFatOnionFailureSpecVector(t *testing.T) {
	t.Parallel()

	vectorBytes, err := os.ReadFile("testdata/fat_error.json")
	require.NoError(t, err)

	var vector specVector
	require.NoError(t, json.Unmarshal(vectorBytes, &vector))

	failureData, err := hex.DecodeString(vector.EncodedFailureMessage)
	require.NoError(t, err)

	paymentPath, err := getSpecPubKeys()
	require.NoError(t, err)

	sessionKey, err := getSpecSessionKey()
	require.NoError(t, err)

	var obfuscatedData []byte
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	for i, test := range vector.Hops {
		// Decode the shared secret and check that it matchs with
		// specification.
		expectedSharedSecret, err := hex.DecodeString(test.SharedSecret)
		require.NoError(t, err)

		obfuscator := NewOnionFatErrorEncrypter(
			sharedSecrets[len(sharedSecrets)-1-i], fatErrorTestStructure,
		)

		require.Equal(t, expectedSharedSecret, obfuscator.sharedSecret[:])

		payload := [8]byte{0, 0, 0, 0, 0, 0, 0, byte(i + 1)}

		if i == 0 {
			// Emulate the situation when last hop creates the onion failure
			// message and send it back.
			obfuscatedData, err = obfuscator.EncryptError(
				true, failureData, payload[:],
			)
			require.NoError(t, err)
		} else {
			// Emulate the situation when forward node obfuscates
			// the onion failure.
			obfuscatedData, err = obfuscator.EncryptError(
				false, obfuscatedData, payload[:],
			)
			require.NoError(t, err)
		}

		// Decode the obfuscated data and check that it matches the
		// specification.
		expectedEncryptErrorData, err := hex.DecodeString(test.EncryptedMessage)
		require.NoError(t, err)
		require.Equal(t, expectedEncryptErrorData, obfuscatedData)
	}

	deobfuscator := NewOnionFatErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, fatErrorTestStructure)

	// Emulate that sender node receives the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// Check that message have been properly de-obfuscated.
	require.Equal(t, decryptedError.Message, failureData)

	// We should understand the node from which error have been received.
	require.Equal(t,
		decryptedError.Sender.SerializeCompressed(),
		paymentPath[len(paymentPath)-1].SerializeCompressed(),
	)

	require.Equal(t, len(paymentPath), decryptedError.SenderIdx)
}

// TestFatOnionFailureZeroesMessage checks that a garbage failure is attributed
// to the first hop.
func TestFatOnionFailureZeroesMessage(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionFatErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, fatErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	obfuscatedData := make([]byte, 20000)

	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	require.Equal(t, 1, decryptedError.SenderIdx)
}

// TestFatOnionFailureShortMessage checks that too short failure is attributed
// to the first hop.
func TestFatOnionFailureShortMessage(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionFatErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, fatErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	obfuscatedData := make([]byte, deobfuscator.hmacsAndPayloadsLen-1)

	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	require.Equal(t, 1, decryptedError.SenderIdx)
}

func generateRandomPath(t *testing.T) (*btcec.PrivateKey, []*btcec.PublicKey) {
	paymentPath := make([]*btcec.PublicKey, 5)
	for i := 0; i < len(paymentPath); i++ {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		paymentPath[i] = privKey.PubKey()
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{'A'}, 32))

	return sessionKey, paymentPath
}
