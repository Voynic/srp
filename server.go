package srp

import "errors"

//
// Handshake
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
    return nil, nil, errors.New("Server found \"A\" to be zero. Aborting handshake.")
  }

  // Create a random secret "b"
  b, err := randomBytes(32)
  if err != nil {
    return nil, nil, err
  }

  // Calculate the SRP-6a version of the multiplier parameter "k"
  k := Hash(dGrp.N, dGrp.g)

  // Compute a value "B" based on "b"
  B := dGrp.add(dGrp.mul(k, v), dGrp.exp(dGrp.g, b))

  // Calculate "u"
  u := Hash(A, B)

  // Compute the pseudo-session key, "S"
  //  S = (Av^u) ^ b
  S := dGrp.exp(dGrp.mul(A, dGrp.exp(v, u)), b)

  // The actual session key is the hash of the pseudo-session key "S"
  K := Hash(S)

  return B, K, nil
}
