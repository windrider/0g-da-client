package batcher

import (
	"encoding/hex"
	"math/big"
	"testing"

	bn254utils "github.com/0glabs/0g-da-client/core/bn254"
	"github.com/0glabs/0g-da-client/core"
	"github.com/0glabs/0g-da-client/disperser/contract/da_signers"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContractG2PointToGnark(t *testing.T) {
	contractG2 := da_signers.BN254G2Point{
		X: [2]*big.Int{
			mustBigInt(t, "11559732032986387107991004021392285783925812861821192530917403151452391805634"),
			mustBigInt(t, "10857046999023057135944570762232829481370756359578518086990519993285655852781"),
		},
		Y: [2]*big.Int{
			mustBigInt(t, "4082367875863433681332203403145435568316851327593401208105741076214120093531"),
			mustBigInt(t, "8495653923123431417604973247489272438418190587263600148770280649306958101930"),
		},
	}
	got := contractG2PointToGnark(contractG2)
	expected := bn254utils.GetG2Generator()
	assert.Equal(t, 0, got.X.A0.Cmp(&expected.X.A0))
	assert.Equal(t, 0, got.X.A1.Cmp(&expected.X.A1))
	assert.Equal(t, 0, got.Y.A0.Cmp(&expected.Y.A0))
	assert.Equal(t, 0, got.Y.A1.Cmp(&expected.Y.A1))
}

func TestContractG2VerifyRoundTrip(t *testing.T) {
	kp, err := core.MakeKeyPairFromString("12345")
	require.NoError(t, err)
	pkG2 := kp.GetPubKeyG2()

	contractG2 := da_signers.BN254G2Point{
		X: [2]*big.Int{pkG2.X.A1.BigInt(new(big.Int)), pkG2.X.A0.BigInt(new(big.Int))},
		Y: [2]*big.Int{pkG2.Y.A1.BigInt(new(big.Int)), pkG2.Y.A0.BigInt(new(big.Int))},
	}
	loaded := contractG2PointToGnark(contractG2)
	assert.True(t, kp.SignMessage([32]byte{1, 2, 3}).Verify(loaded, [32]byte{1, 2, 3}))
}

func TestGetHash(t *testing.T) {
	dataRoot := crypto.Keccak256Hash([]byte("dataRoot"))
	epoch := big.NewInt(123)
	quorumId := big.NewInt(456)
	erasureCommitment := core.NewG1Point(new(big.Int).SetUint64(1), new(big.Int).SetUint64(1))

	expectedHash := [32]byte{0x0d, 0x11, 0x9e, 0x0c, 0xc9, 0x08, 0x65, 0x90, 0x4e, 0x60, 0x35, 0xdc, 0x57, 0xa8, 0x53, 0x6c, 0xee, 0x32, 0xf2, 0xba, 0x20, 0x87, 0x6e, 0xfc, 0x5d, 0x0d, 0xb5, 0xec, 0x4b, 0x02, 0xb7, 0x7a}

	resultHash, err := getHash(dataRoot, epoch, quorumId, erasureCommitment)
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, resultHash, "Hashes should match")
}

func TestBlobVerifiedHashAlignment(t *testing.T) {
	dataRoot, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(t, err)
	var root [32]byte
	copy(root[:], dataRoot)

	commitment := core.NewG1Point(big.NewInt(1), big.NewInt(2))
	wire, err := wireFormatErasureCommitment(commitment)
	require.NoError(t, err)

	hashFromWire, err := getHashFromWire(root, big.NewInt(1), big.NewInt(2), wire)
	require.NoError(t, err)

	msgPoint := bn254utils.MapToCurve(hashFromWire)
	expectedX := mustBigInt(t, "3104132272622526655068902279970515367044771064982988265068273751564440697689")
	expectedY := mustBigInt(t, "14983672482514514723382346054400511740670770934276906876175822994665721348371")
	assert.Equal(t, 0, msgPoint.X.BigInt(new(big.Int)).Cmp(expectedX))
	assert.Equal(t, 0, msgPoint.Y.BigInt(new(big.Int)).Cmp(expectedY))

	kp, err := core.MakeKeyPairFromString("1")
	require.NoError(t, err)
	sig := kp.SignHashedToCurveMessage(&core.G1Point{G1Affine: msgPoint})
	assert.True(t, sig.Verify(kp.GetPubKeyG2(), hashFromWire))
}

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	require.True(t, ok)
	return v
}
