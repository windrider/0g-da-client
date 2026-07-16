package bn254

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestValidateSubmissionSignatureRoundTrip(t *testing.T) {
	sk, err := new(fr.Element).SetString("42")
	require.NoError(t, err)

	pkG1 := MulByGeneratorG1(sk)
	pkG2 := MulByGeneratorG2(sk)

	dataRoot, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(t, err)
	var root [32]byte
	copy(root[:], dataRoot)

	commitX := big.NewInt(1)
	commitY := big.NewInt(2)
	hashPoint := SubmissionDataHash(root, big.NewInt(1), big.NewInt(2), commitX, commitY)
	sig := new(bn254.G1Affine).ScalarMultiplication(hashPoint, sk.BigInt(new(big.Int)))

	sigX := sig.X.BigInt(new(big.Int))
	sigY := sig.Y.BigInt(new(big.Int))
	pkG1X := pkG1.X.BigInt(new(big.Int))
	pkG1Y := pkG1.Y.BigInt(new(big.Int))

	ok, err := ValidateSubmissionSignature(
		sigX, sigY, pkG1X, pkG1Y,
		pkG2.X.A1.BigInt(new(big.Int)), pkG2.X.A0.BigInt(new(big.Int)),
		pkG2.Y.A1.BigInt(new(big.Int)), pkG2.Y.A0.BigInt(new(big.Int)),
		hashPoint,
	)
	require.NoError(t, err)
	require.True(t, ok)
}
