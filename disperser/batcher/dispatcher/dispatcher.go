package dispatcher

import (
	"context"
	"fmt"
	"math/big"

	"encoding/hex"

	"github.com/0glabs/0g-da-client/common"
	"github.com/0glabs/0g-da-client/core"
	bn254utils "github.com/0glabs/0g-da-client/core/bn254"
	"github.com/0glabs/0g-da-client/disperser"
	"github.com/0glabs/0g-da-client/disperser/batcher/transactor"
	"github.com/0glabs/0g-da-client/disperser/contract"
	"github.com/0glabs/0g-da-client/disperser/contract/da_entrance"
	zg_core "github.com/0glabs/0g-storage-client/core"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-merkletree"
	"github.com/wealdtech/go-merkletree/keccak256"
)

type dispatcher struct {
	daContract *contract.DAContract

	transactor *transactor.Transactor

	logger common.Logger
}

func NewDispatcher(transactor *transactor.Transactor, daContract *contract.DAContract, logger common.Logger) (*dispatcher, error) {
	return &dispatcher{
		logger:     logger,
		daContract: daContract,
		transactor: transactor,
	}, nil
}

var _ disperser.Dispatcher = (*dispatcher)(nil)

func DumpEncodedBlobs(extendedMatrix []*core.ExtendedMatrix) ([]byte, error) {
	blobLocations := make([]*core.BlobLocation, len(extendedMatrix))
	for i, matrix := range extendedMatrix {
		rows := matrix.GetRows()
		cols := matrix.GetCols()
		blobLocations[i] = &core.BlobLocation{
			Rows:           uint(rows),
			Cols:           uint(cols),
			SegmentIndexes: make([]uint, rows),
			Offsets:        make([]uint, rows),
		}
	}
	segmentNum := core.AllocateRows(blobLocations)
	res := make([]byte, segmentNum*core.SegmentSize)
	for i, location := range blobLocations {
		for j := range location.SegmentIndexes {
			offset := location.SegmentIndexes[j]*core.SegmentSize + location.Offsets[j]
			coeffs := extendedMatrix[i].GetRowInBytes(j)
			commitment := extendedMatrix[i].Commitments[j][:]
			copy(res[offset:], coeffs)
			copy(res[offset+uint(len(coeffs)):], commitment)
		}
	}
	return res, nil
}

func (c *dispatcher) DisperseBatch(ctx context.Context, batchHeaderHash [32]byte, batchHeader *core.BatchHeader, blobCommitments []*core.BlobCommitments, blobHeaders []*core.BlobHeader) (eth_common.Hash, error) {
	n := len(blobCommitments)
	dataRoots := make([]eth_common.Hash, n)

	for i, commit := range blobCommitments {
		if len(commit.EncodedData) > 0 {
			// encoded blobs
			encodedBlobsData, err := zg_core.NewDataInMemory(commit.EncodedData)
			if err != nil {
				return eth_common.Hash{}, errors.WithMessage(err, "failed to build encoded blobs data")
			}

			// c.logger.Info("[dispatcher] Data prepared to upload", "size", data.Size(), "chunks", data.NumChunks(), "segments", data.NumSegments())

			// Calculate file merkle root.
			tree, err := zg_core.MerkleTree(encodedBlobsData)
			if err != nil {
				return eth_common.Hash{}, errors.WithMessage(err, "Failed to create data merkle tree")
			}
			c.logger.Info("[dispatcher] data merkle root calculated", "root", tree.Root())
			dataRoots[i] = tree.Root()

			if eth_common.BytesToHash(blobCommitments[i].StorageRoot) != dataRoots[i] {
				return eth_common.Hash{}, fmt.Errorf("data merkle root is not match: local: %v, encoder: %v", dataRoots[i], eth_common.BytesToHash(blobCommitments[i].StorageRoot))
			}
		} else {
			dataRoots[i] = eth_common.BytesToHash(blobCommitments[i].StorageRoot)
		}
	}

	leafs := make([][]byte, len(dataRoots))
	for i, dataRoot := range dataRoots {
		leafs[i] = dataRoot[:]
	}
	tree, err := merkletree.NewTree(merkletree.WithData(leafs), merkletree.WithHashType(keccak256.New()))
	if err != nil {
		return eth_common.Hash{}, fmt.Errorf("failed to get batch data root: %v", err)
	}
	batchHeader.DataRoot = eth_common.Hash(tree.Root())

	// upload batchly
	txHash, err := c.transactor.BatchUpload(c.daContract, dataRoots)
	if err != nil {
		return eth_common.Hash{}, fmt.Errorf("failed to submit blob data roots: %v", err)
	}

	return txHash, nil
}

func (c *dispatcher) SubmitAggregateSignatures(ctx context.Context, rootSubmission []*core.CommitRootSubmission) (eth_common.Hash, error) {
	submissions := make([]da_entrance.IDAEntranceCommitRootSubmission, len(rootSubmission))
	c.logger.Debug("[dispatcher] submit aggregate signatures", "size", len(rootSubmission))
	for i, s := range rootSubmission {
		commitX, commitY, err := s.ErasureCommitment.ContractBN254Coords()
		if err != nil {
			return eth_common.Hash{}, fmt.Errorf("failed to encode erasure commitment: %w", err)
		}
		sigX, sigY, err := s.AggSigs.ContractBN254Coords()
		if err != nil {
			return eth_common.Hash{}, fmt.Errorf("failed to encode signature: %w", err)
		}
		c.logger.Info("Submit Aggregate Signatures", "root", hex.EncodeToString(s.DataRoot[:]), "epoch", s.Epoch.String(), "quorum", s.QuorumId.String(), "X", commitX.String(), "Y", commitY.String())
		submissions[i] = da_entrance.IDAEntranceCommitRootSubmission{
			DataRoot: s.DataRoot,
			Epoch:    s.Epoch,
			QuorumId: s.QuorumId,
			ErasureCommitment: da_entrance.BN254G1Point{
				X: commitX,
				Y: commitY,
			},
			QuorumBitmap: s.QuorumBitmap,
			AggPkG2: da_entrance.BN254G2Point{
				X: [2]*big.Int{
					s.AggPkG2.X.A1.BigInt(new(big.Int)),
					s.AggPkG2.X.A0.BigInt(new(big.Int)),
				},
				Y: [2]*big.Int{
					s.AggPkG2.Y.A1.BigInt(new(big.Int)),
					s.AggPkG2.Y.A0.BigInt(new(big.Int)),
				},
			},
			Signature: da_entrance.BN254G1Point{
				X: sigX,
				Y: sigY,
			},
		}

		aggPkG1, err := c.daContract.GetAggPkG1(nil, s.Epoch, s.QuorumId, s.QuorumBitmap)
		if err != nil {
			return eth_common.Hash{}, fmt.Errorf("failed to get agg pkG1: %w", err)
		}
		hashPoint := bn254utils.SubmissionDataHash(s.DataRoot, s.Epoch, s.QuorumId, commitX, commitY)
		valid, err := bn254utils.ValidateSubmissionSignature(
			sigX, sigY,
			aggPkG1.AggPkG1.X, aggPkG1.AggPkG1.Y,
			submissions[i].AggPkG2.X[0], submissions[i].AggPkG2.X[1],
			submissions[i].AggPkG2.Y[0], submissions[i].AggPkG2.Y[1],
			hashPoint,
		)
		if err != nil {
			return eth_common.Hash{}, fmt.Errorf("submission signature validation error: %w", err)
		}
		if !valid {
			return eth_common.Hash{}, fmt.Errorf("submission signature invalid (local gamma pairing check failed)")
		}
		c.logger.Info("Submit Aggregate Signatures validated", "root", hex.EncodeToString(s.DataRoot[:]), "hit", aggPkG1.Hit.String(), "total", aggPkG1.Total.String())
	}

	txHash, err := c.transactor.SubmitVerifiedCommitRoots(c.daContract, submissions)
	if err != nil {
		return eth_common.Hash{}, fmt.Errorf("failed to submit verified commit roots: %v", err)
	}

	return txHash, nil
}
