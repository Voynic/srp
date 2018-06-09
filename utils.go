package srp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

//
// Returns true if a byte slice is equal to 0
//
func isZero(x []byte) bool {
	// Convert x1 from []byte -> *Int
	xBigInt := big.NewInt(0).SetBytes(x)

	// Define a 0 big int to compare to xBigInt
	zeroBigInt := big.NewInt(0)

	isZero := xBigInt.Cmp(zeroBigInt) == 0

	return isZero
}

//
// Get n random bytes. Returns a byte slice.
//
func randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

//
// Joins and hashes (SHA-256) an arbitrary number of byte slices.
//
// NOTE: Exported because it is used in post key negotiation proof.
//
func Hash(x ...[]byte) []byte {
	// Join all byte slices in "x" ([][]byte)
	joinedBytes := bytes.Join(x, nil)

	// Take the SHA-256 hash of the joined bytes
	hash := sha256.Sum256(joinedBytes)

	// Return the hash as a byte slice (rather than byte array)
	return hash[:]
}

// Pad -
//
// Pad a byte slice with leading zeros.
//
func Pad(bytes []byte, length int) []byte {
	// In cases where the desired padding length is less than or equal to the
	//	length of the provided bytes, just return bytes.
	if length <= len(bytes) {
		return bytes
	}

	// The number of padding bytes to prepend before the provided bytes
	paddingLength := length - len(bytes)

	// The byte slice to prepend before the provided bytes
	paddingBytes := make([]byte, paddingLength)

	// Return [padding bytes] + [provided bytes]
	return append(paddingBytes, bytes...)
}
