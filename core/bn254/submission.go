package bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// SubmissionDataHash matches SubmissionLib.dataHash: hashToG1(keccak256(encodePacked(...))).
func SubmissionDataHash(dataRoot [32]byte, epoch, quorumId, commitX, commitY *big.Int) *bn254.G1Affine {
	var packed []byte
	packed = append(packed, dataRoot[:]...)
	packed = append(packed, math.U256Bytes(epoch)...)
	packed = append(packed, math.U256Bytes(quorumId)...)
	packed = append(packed, math.U256Bytes(commitX)...)
	packed = append(packed, math.U256Bytes(commitY)...)
	digest := crypto.Keccak256Hash(packed)
	return MapToCurve(digest)
}

// SubmissionGamma matches SubmissionLib.validateSignature gamma packing order.
func SubmissionGamma(
	sigX, sigY, aggPkG1X, aggPkG1Y *big.Int,
	aggPkG2X0, aggPkG2X1, aggPkG2Y0, aggPkG2Y1 *big.Int,
	hashX, hashY *big.Int,
) *big.Int {
	var packed []byte
	packed = append(packed, math.U256Bytes(sigX)...)
	packed = append(packed, math.U256Bytes(sigY)...)
	packed = append(packed, math.U256Bytes(aggPkG1X)...)
	packed = append(packed, math.U256Bytes(aggPkG1Y)...)
	packed = append(packed, math.U256Bytes(aggPkG2X0)...)
	packed = append(packed, math.U256Bytes(aggPkG2X1)...)
	packed = append(packed, math.U256Bytes(aggPkG2Y0)...)
	packed = append(packed, math.U256Bytes(aggPkG2Y1)...)
	packed = append(packed, math.U256Bytes(hashX)...)
	packed = append(packed, math.U256Bytes(hashY)...)
	gamma := new(big.Int).SetBytes(crypto.Keccak256(packed))
	gamma.Mod(gamma, fr.Modulus())
	return gamma
}

func g1FromBigInts(x, y *big.Int) *bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	return &p
}

func g2FromContract(x0, x1, y0, y1 *big.Int) *bn254.G2Affine {
	var p bn254.G2Affine
	p.X.A0.SetBigInt(x1)
	p.X.A1.SetBigInt(x0)
	p.Y.A0.SetBigInt(y1)
	p.Y.A1.SetBigInt(y0)
	return &p
}

// ValidateSubmissionSignature matches DAEntrance SubmissionLib.validateSignature pairing.
func ValidateSubmissionSignature(
	sigX, sigY, aggPkG1X, aggPkG1Y *big.Int,
	aggPkG2X0, aggPkG2X1, aggPkG2Y0, aggPkG2Y1 *big.Int,
	hashPoint *bn254.G1Affine,
) (bool, error) {
	hashX := hashPoint.X.BigInt(new(big.Int))
	hashY := hashPoint.Y.BigInt(new(big.Int))
	gamma := SubmissionGamma(sigX, sigY, aggPkG1X, aggPkG1Y, aggPkG2X0, aggPkG2X1, aggPkG2Y0, aggPkG2Y1, hashX, hashY)

	sig := g1FromBigInts(sigX, sigY)
	aggPkG1 := g1FromBigInts(aggPkG1X, aggPkG1Y)
	aggPkG2 := g2FromContract(aggPkG2X0, aggPkG2X1, aggPkG2Y0, aggPkG2Y1)

	p0 := new(bn254.G1Affine).Add(sig, new(bn254.G1Affine).ScalarMultiplication(aggPkG1, gamma))
	p1 := new(bn254.G1Affine).Add(hashPoint, new(bn254.G1Affine).ScalarMultiplication(GetG1Generator(), gamma))
	negG2 := new(bn254.G2Affine).Neg(GetG2Generator())

	return bn254.PairingCheck(
		[]bn254.G1Affine{*p0, *p1},
		[]bn254.G2Affine{*negG2, *aggPkG2},
	)
}
