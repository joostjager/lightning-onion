package sphinx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestFatOnionFailure checks the ability of sender of payment to decode the
// obfuscated onion error.
func TestFatOnionFailure(t *testing.T) {
	// Create numHops random sphinx paymentPath.
	paymentPath := make([]*btcec.PublicKey, 5)
	for i := 0; i < len(paymentPath); i++ {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		paymentPath[i] = privKey.PubKey()
	}
	sessionKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{'A'}, 32))

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength-sha256.Size)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := &OnionErrorEncrypter{
		sharedSecret: sharedSecrets[len(errorPath)-1],
	}

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	const finalHoldTimeMs = 1
	obfuscatedData := obfuscator.EncryptFatError(true, failureData, finalHoldTimeMs)
	holdTimesMs := []uint64{finalHoldTimeMs}

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = &OnionErrorEncrypter{
			sharedSecret: sharedSecrets[i],
		}

		intermediateHoldTimeMs := uint64(100 + i)
		obfuscatedData = obfuscator.EncryptFatError(
			false, obfuscatedData, intermediateHoldTimeMs,
		)
		holdTimesMs = append([]uint64{intermediateHoldTimeMs}, holdTimesMs...)
	}

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	})

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptFatError(obfuscatedData)
	require.NoError(t, err)

	// We should understand the node from which error have been received.
	require.Equal(t,
		errorPath[len(errorPath)-1].SerializeCompressed(),
		decryptedError.Sender.SerializeCompressed())

	require.Equal(t, len(errorPath), decryptedError.SenderIdx)

	// Check that message have been properly de-obfuscated.
	require.Equal(t, failureData, decryptedError.Message)
	require.Equal(t, holdTimesMs, decryptedError.HoldTimesMs)
}

// TestOnionFailureCorruption checks the ability of sender of payment to
// identify a node on the path that corrupted the failure message.
func TestOnionFailureCorruption(t *testing.T) {
	// Create numHops random sphinx paymentPath.
	paymentPath := make([]*btcec.PublicKey, 5)
	for i := 0; i < len(paymentPath); i++ {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		paymentPath[i] = privKey.PubKey()
	}
	sessionKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{'A'}, 32))

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength-sha256.Size)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := &OnionErrorEncrypter{
		sharedSecret: sharedSecrets[len(errorPath)-1],
	}

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	obfuscatedData := obfuscator.EncryptFatError(true, failureData, 1)

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = &OnionErrorEncrypter{
			sharedSecret: sharedSecrets[i],
		}
		obfuscatedData = obfuscator.EncryptFatError(false, obfuscatedData, uint64(100+i))

		// Hop 1 (the second hop from the sender pov) is corrupting the failure
		// message.
		if i == 1 {
			obfuscatedData[0] ^= 255
		}
	}

	// Emulate creation of the deobfuscator on the receiving onion error side.
	deobfuscator := NewOnionErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	})

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptFatError(obfuscatedData)
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
	vectorBytes, err := os.ReadFile("fat_error.json")
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

		obfuscator := &OnionErrorEncrypter{
			sharedSecret: sharedSecrets[len(sharedSecrets)-1-i],
		}

		var b bytes.Buffer
		require.NoError(t, obfuscator.Encode(&b))

		obfuscator2 := &OnionErrorEncrypter{}
		obfuscatorReader := bytes.NewReader(b.Bytes())
		require.NoError(t, obfuscator2.Decode(obfuscatorReader))

		require.Equal(t, obfuscator, obfuscator2)
		require.Equal(t, expectedSharedSecret, obfuscator.sharedSecret[:])

		if i == 0 {
			// Emulate the situation when last hop creates the onion failure
			// message and send it back.
			obfuscatedData = obfuscator.EncryptFatError(true, failureData, uint64(i+1))
		} else {
			// Emulate the situation when forward node obfuscates
			// the onion failure.
			obfuscatedData = obfuscator.EncryptFatError(false, obfuscatedData, uint64(i+1))
		}

		// Decode the obfuscated data and check that it matches the
		// specification.
		expectedEncryptErrordData, err := hex.DecodeString(test.EncryptedMessage)
		require.NoError(t, err)
		require.Equal(t, expectedEncryptErrordData, obfuscatedData)
	}

	deobfuscator := NewOnionErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	})

	// Emulate that sender node receives the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptFatError(obfuscatedData)
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
