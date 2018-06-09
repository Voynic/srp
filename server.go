package srp

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Handshake -
//
// Params:
//  A ([]byte) - a client's generated public key
//  v ([]byte) - a client's stored verifer
//
// Return:
//  []byte - the generated public key "B", to be sent to the client
//  []byte - the computed session key "K", to be kept secret
//  error
//
//  NOTE Be very careful not to confuse the secret key "K", and the public key
//       "B". Both are returned by this function, but unlike "B", "K" must never
//       be transmitted to the client.
//
func Handshake(A, v []byte) ([]byte, []byte, error) {
	// "A" cannot be zero
	if isZero(A) {
		return nil, nil, errors.New("Server found \"A\" to be zero. Aborting handshake")
	}

	// Create a random secret "b"
	b, err := randomBytes(32)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the SRP-6a version of the multiplier parameter "k"
	// TODO: Pad g
	k := Hash(Pad(dGrp.N, 512), Pad(dGrp.g, 512))
	fmt.Println("srp_k:  " + base64.StdEncoding.EncodeToString(k))

	// Compute a value "B" based on "b"
	//   B = (v + g^b) % N
	B := dGrp.add(dGrp.mul(k, v), dGrp.exp(dGrp.g, b))

	// Calculate "u"
	// TODO: Pad A and B
	u := Hash(Pad(A, 512), Pad(B, 512))
	fmt.Println("srp_u:  " + base64.StdEncoding.EncodeToString(u))

	// Compute the pseudo-session key, "S"
	//  S = (Av^u) ^ b
	S := dGrp.exp(dGrp.mul(A, dGrp.exp(v, u)), b)
	fmt.Println("srp_S:  " + base64.StdEncoding.EncodeToString(S))

	// The actual session key is the hash of the pseudo-session key "S"
	K := Hash(S)
	fmt.Println("srp_K:  " + base64.StdEncoding.EncodeToString(K))

	return B, K, nil
}
