package batcher

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/0glabs/0g-da-client/common"
	"github.com/0glabs/0g-da-client/common/geth"
	"github.com/0glabs/0g-da-client/core"
	"github.com/0glabs/0g-da-client/disperser"
	pb "github.com/0glabs/0g-da-client/disperser/api/grpc/signer"
	"github.com/0glabs/0g-da-client/disperser/contract"
	"github.com/0glabs/0g-da-client/disperser/contract/da_signers"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/wealdtech/go-merkletree"
	"github.com/hashicorp/go-multierror"
)

var errNoSignedResults = errors.New("no signed results")

type SignatureSizeNotifier struct {
	mu sync.Mutex

	Notify    chan struct{}
	threshold uint64
	// active is set to false after the notifier is triggered to prevent it from triggering again for the same batch
	// This is reset when CreateBatch is called and the encoded results have been consumed
	active bool
}

func NewSignatureSizeNotifier(notify chan struct{}, threshold uint64) *SignatureSizeNotifier {
	return &SignatureSizeNotifier{
		Notify:    notify,
		threshold: threshold,
		active:    true,
	}
}

type SignerConfig struct {
	// the timeout for each signing request
	SigningRequestTimeout time.Duration

	MaxNumRetriesPerBlob uint

	MaxNumRetriesSign uint

	SigningInterval time.Duration
}

type SignInfo struct {
	headerHash [32]byte
	batch      *batch
	ts         uint64
	proofs     []*merkletree.Proof
	reties     uint

	epoch    *big.Int
	quorumId *big.Int
	signers  map[eth_common.Address]*SignerState
}

type SignRequestResult struct {
	signatures []*core.Signature
	signer     eth_common.Address
}

type SignRequestResultOrStatus struct {
	SignRequestResult
	Err error
}

type SignerInfo struct {
	Signer eth_common.Address
	Socket string
	PkG1   *core.G1Point
	PkG2   *core.G2Point
}

type SignerState struct {
	*SignerInfo
	sliceIndexes []int
}

type BatchCommitRootSubmission struct {
	submissions []*core.CommitRootSubmission
	headerHash  [32]byte
	batch       *batch
	ts          uint64
	proofs      []*merkletree.Proof
}

type SliceSigner struct {
	SignerConfig

	mu sync.RWMutex

	Pool                  common.WorkerPool
	SignatureSizeNotifier *SignatureSizeNotifier
	SignerChan            chan *SignInfo

	EncodingStreamer *EncodingStreamer
	Finalizer        Finalizer

	pendingBatches       []*SignInfo
	pendingBatchesToSign []*SignInfo
	pendingSubmissions   map[uint64]*BatchCommitRootSubmission
	signedBatching       map[uint64]uint64
	signedBatches        map[uint64][]uint64
	signedBlobSize       uint64

	daContract   *contract.DAContract
	signerClient disperser.SignerClient

	retryOption contract.RetryOption

	blobStore disperser.BlobStore
	metrics   *Metrics

	logger common.Logger

	SignedBatchSize uint
}

func NewEncodedSliceSigner(
	ethConfig geth.EthClientConfig,
	config SignerConfig,
	workerPool common.WorkerPool,
	signatureSizeNotifier *SignatureSizeNotifier,
	signerClient disperser.SignerClient,
	blobStore disperser.BlobStore,
	daContract *contract.DAContract,
	metrics *Metrics,
	logger common.Logger) (*SliceSigner, error) {
	return &SliceSigner{
		SignerConfig:          config,
		Pool:                  workerPool,
		SignatureSizeNotifier: signatureSizeNotifier,
		SignerChan:            make(chan *SignInfo),
		daContract:            daContract,
		signerClient:          signerClient,
		retryOption: contract.RetryOption{
			Rounds:   ethConfig.ReceiptPollingRounds,
			Interval: ethConfig.ReceiptPollingInterval,
		},
		blobStore: blobStore,
		metrics:   metrics,
		logger:    logger,

		pendingBatches:       make([]*SignInfo, 0),
		pendingBatchesToSign: make([]*SignInfo, 0),
		pendingSubmissions:   make(map[uint64]*BatchCommitRootSubmission),
		signedBatching:       make(map[uint64]uint64),
		signedBatches:        make(map[uint64][]uint64),
		signedBlobSize:       0,
		SignedBatchSize:      0,
	}, nil
}

func (s *SliceSigner) Start(ctx context.Context) error {
	// goroutine for making blob signing requests
	go func() {
		ticker := time.NewTicker(s.SigningInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				signInfo := s.getPendingBatchToSign()
				if signInfo != nil {
					err := s.doSigning(ctx, signInfo)
					if err != nil {
						s.logger.Error("[signer] error during requesting signing", "err", err)
					}
				}

			}
		}
	}()

	// goroutine for wait tx finalized
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				signInfo := s.getPendingBatch()
				if signInfo != nil {
					err := s.waitBatchTxFinalized(ctx, signInfo)
					if err != nil {
						s.logger.Warn("[signer] error wait batch tx finalized", "err", err)
					}
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case batchInfo := <-s.SignerChan:
				s.putPendingBatches(batchInfo)
			}
		}
	}()

	return nil

}

func (s *SliceSigner) putPendingBatches(info *SignInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingBatches = append(s.pendingBatches, info)
	s.logger.Info(`[signer] received pending batch for sign`, "queue size", len(s.pendingBatches))
}

func (s *SliceSigner) getPendingBatch() *SignInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pendingBatches) == 0 {
		return nil
	}
	info := s.pendingBatches[0]
	s.pendingBatches = s.pendingBatches[1:]
	s.logger.Info(`[signer] wait one pending batch for sign`, "queue size", len(s.pendingBatches))
	return info
}

func (s *SliceSigner) waitBatchTxFinalized(ctx context.Context, batchInfo *SignInfo) error {
	dataUploadEvents, blockNumber, err := s.waitForReceipt(batchInfo.batch.TxHash)
	s.logger.Debug("[signer] batch tx finalized", "event size", len(dataUploadEvents), "block number", blockNumber)

	if err != nil || len(dataUploadEvents) == 0 {
		// batch is not confirmed
		_ = s.handleFailure(ctx, batchInfo.batch.BlobMetadata, FailBatchReceipt)
		s.EncodingStreamer.RemoveBatchingStatus(batchInfo.ts)
		return err
	}

	for i := 1; i < len(dataUploadEvents); i++ {
		if dataUploadEvents[i].Epoch.Cmp(dataUploadEvents[i-1].Epoch) != 0 {
			_ = s.handleFailure(ctx, batchInfo.batch.BlobMetadata, FailBatchEpochMismatch)
			s.EncodingStreamer.RemoveBatchingStatus(batchInfo.ts)
			return fmt.Errorf("epoch in one batch is mismatch: epoch %v, %v", dataUploadEvents[i].Epoch, dataUploadEvents[i-1].Epoch)
		}
	}

	epoch := dataUploadEvents[0].Epoch
	quorumId := dataUploadEvents[0].QuorumId
	signers, err := s.getSigners(epoch, quorumId)
	if err != nil {
		// if signInfo.reties < s.MaxNumRetriesSign {
		// 	s.mu.Lock()
		// 	defer s.mu.Unlock()

		// 	signInfo.reties += 1
		// 	s.pendingBatchesToSign = append(s.pendingBatchesToSign, signInfo)
		// } else {
		_ = s.handleFailure(ctx, batchInfo.batch.BlobMetadata, FailGetSigners)
		s.EncodingStreamer.RemoveBatchingStatus(batchInfo.ts)
		// }

		return fmt.Errorf("failed to get signers from contract: %w", err)
	}

	// update epoch
	batchInfo.epoch = epoch
	batchInfo.quorumId = quorumId
	batchInfo.signers = signers

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingBatchesToSign = append(s.pendingBatchesToSign, batchInfo)
	s.logger.Info("[signer] blob epoch status", "ts", batchInfo.ts, "epoch", epoch, "quorum", quorumId, "unique signers", len(signers))
	return nil
}

func (s *SliceSigner) waitForReceipt(txHash eth_common.Hash) ([]*contract.DataUploadEvent, uint32, error) {
	if txHash.Cmp(eth_common.Hash{}) == 0 {
		return nil, 0, errors.New("empty transaction hash")
	}
	s.logger.Info("[signer] waiting batch tx be confirmed", "tx hash", txHash)
	// data is not duplicate, there is a new transaction
	var blockNumber uint64
	submitEventHash := eth_common.HexToHash(contract.DataUploadEventHash)
	var submissions []*contract.DataUploadEvent

	for {
		receipt, err := s.daContract.WaitForReceipt(txHash, true, s.retryOption)
		if err != nil {
			return nil, 0, err
		}

		blockNumber = receipt.BlockNumber
		s.logger.Debug("[signer] waiting batch tx to be confirmed", "receipt block", blockNumber, "finalized block", s.Finalizer.LatestFinalizedBlock())

		if blockNumber > s.Finalizer.LatestFinalizedBlock() {
			time.Sleep(time.Second * 5)
			continue
		}

		// parse submission from event log
		for _, v := range receipt.Logs {
			if v.Topics[0] == submitEventHash {
				log := contract.ConvertToGethLog(v)

				submission, err := s.daContract.ParseDataUpload(*log)
				if err != nil {
					return nil, 0, err
				}

				submissions = append(submissions, &contract.DataUploadEvent{
					DataRoot: submission.DataRoot,
					Epoch:    submission.Epoch,
					QuorumId: submission.QuorumId,
				})
			}
		}
		break
	}

	return submissions, uint32(blockNumber), nil
}

func (s *SliceSigner) getSigners(epoch *big.Int, quorumId *big.Int) (map[eth_common.Address]*SignerState, error) {
	// Get quorum signers from chain (quorum length is always 1024)
	signerAddresses, err := s.daContract.GetQuorum(nil, epoch, quorumId)
	s.logger.Debug("[signer] get signers for quorum", "size", len(signerAddresses))

	if err != nil {
		return nil, err
	}

	if len(signerAddresses) == 0 {
		return nil, fmt.Errorf("signer is none")
	}

	hm := make(map[eth_common.Address]*SignerState)
	uniqueAddress := make([]eth_common.Address, 0)
	for sliceIdx, address := range signerAddresses {
		if state, ok := hm[address]; !ok {
			hm[address] = &SignerState{
				SignerInfo:   nil,
				sliceIndexes: []int{sliceIdx},
			}
			uniqueAddress = append(uniqueAddress, address)
		} else {
			state.sliceIndexes = append(state.sliceIndexes, sliceIdx)
		}
	}

	signers, err := s.daContract.GetSigner(nil, uniqueAddress)
	if err != nil {
		return nil, err
	}

	for _, signer := range signers {
		pubkeyG1 := core.NewG1Point(signer.PkG1.X, signer.PkG1.Y)
		pubkeyG2 := contractG2PointToGnark(signer.PkG2)

		hm[signer.Signer].SignerInfo = &SignerInfo{
			Signer: signer.Signer,
			Socket: signer.Socket,
			PkG1:   pubkeyG1,
			PkG2:   pubkeyG2,
		}
	}

	return hm, nil
}

func (s *SliceSigner) handleFailure(ctx context.Context, blobMetadatas []*disperser.BlobMetadata, reason FailReason) error {
	var result *multierror.Error
	for _, metadata := range blobMetadatas {
		err := s.blobStore.HandleBlobFailure(ctx, metadata, s.MaxNumRetriesPerBlob)
		if err != nil {
			s.logger.Error("[signer] error handling blob failure", "err", err)
			// Append the error
			result = multierror.Append(result, err)
		}
		s.metrics.UpdateCompletedBlob(int(metadata.RequestMetadata.BlobSize), disperser.Failed)
	}
	s.metrics.UpdateBatchError(reason, len(blobMetadatas))

	// Return the error(s)
	return result.ErrorOrNil()
}

func (s *SliceSigner) getPendingBatchToSign() *SignInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pendingBatchesToSign) == 0 {
		return nil
	}
	info := s.pendingBatchesToSign[0]
	s.pendingBatchesToSign = s.pendingBatchesToSign[1:]
	s.logger.Info(`[signer] retrieved one batch to sign`, "queue size", len(s.pendingBatchesToSign))
	return info
}

func (s *SliceSigner) doSigning(ctx context.Context, signInfo *SignInfo) error {
	requestData := s.assignEncodedBlobs(signInfo.signers, signInfo.batch, signInfo.epoch.Uint64(), signInfo.quorumId.Uint64())
	if len(requestData) == 0 {
		s.logger.Warn("[signer] data for sign is empty")
		return nil
	}

	update := make(chan SignRequestResultOrStatus, len(requestData))
	for signerAddress, content := range requestData {
		address := eth_common.BytesToAddress(signerAddress[:])
		requests := make([]*pb.SignRequest, len(content))
		copy(requests, content)
		encodingCtx, cancel := context.WithTimeout(ctx, s.SigningRequestTimeout)
		s.Pool.Submit(func() {
			defer cancel()

			// Todo: assume this is no empty EncodedSlice
			// n := 0
			// for _, req := range reqs[i] {
			// 	if len(req.EncodedSlice) != 0 {
			// 		reqs[i][n] = req
			// 		n++
			// 	}
			// }

			reply, err := s.signerClient.BatchSign(encodingCtx, signInfo.signers[address].Socket, requests, s.logger)
			if err != nil {
				update <- SignRequestResultOrStatus{
					Err:               err,
					SignRequestResult: SignRequestResult{signer: address},
				}
				return
			}

			update <- SignRequestResultOrStatus{
				Err: nil,
				SignRequestResult: SignRequestResult{
					signatures: reply,
					signer:     address,
				},
			}
		})

		s.logger.Trace("[signer] requested sign for batch", "ts", signInfo.ts, "signer", address)
	}

	err := s.aggregateSignature(ctx, signInfo, update)
	if err != nil {
		return err
	}

	return nil
}

func (s *SliceSigner) assignEncodedBlobs(signers map[eth_common.Address]*SignerState, batch *batch, epoch uint64, quorumId uint64) map[eth_common.Address][]*pb.SignRequest {
	requestData := make(map[eth_common.Address][]*pb.SignRequest)
	for blobIdx, encodedBlobs := range batch.EncodedBlobs {
		for addr, state := range signers {
			if _, ok := requestData[addr]; !ok {
				requestData[addr] = make([]*pb.SignRequest, len(batch.EncodedBlobs))
			}

			if requestData[addr][blobIdx] == nil {
				commitment, err := wireFormatErasureCommitment(encodedBlobs.ErasureCommitment)
				if err != nil {
					s.logger.Error("[signer] failed to encode erasure commitment", "err", err)
					continue
				}

				requestData[addr][blobIdx] = &pb.SignRequest{
					Epoch:             epoch,
					QuorumId:          quorumId,
					ErasureCommitment: commitment,
					StorageRoot:       encodedBlobs.StorageRoot,
					EncodedSlice:      make([][]byte, 0),
				}
			}

			for _, sliceIdx := range state.sliceIndexes {
				requestData[addr][blobIdx].EncodedSlice = append(requestData[addr][blobIdx].EncodedSlice, encodedBlobs.EncodedSlice[sliceIdx])
			}
		}
	}

	return requestData
}

func (s *SliceSigner) aggregateSignature(ctx context.Context, signInfo *SignInfo, update chan SignRequestResultOrStatus) error {
	signerCounter := len(signInfo.signers)

	blobSize := len(signInfo.batch.EncodedBlobs)
	erasureCommitments := make([]*core.G1Point, blobSize)
	storageRoots := make([][32]byte, blobSize)
	messages := make([][32]byte, blobSize)
	for blobIdx, encodedBlobs := range signInfo.batch.EncodedBlobs {
		var dataRoot [32]byte
		copy(dataRoot[:], encodedBlobs.StorageRoot[:32])

		erasureCommitments[blobIdx] = encodedBlobs.ErasureCommitment
		storageRoots[blobIdx] = dataRoot
		wireCommitment, err := wireFormatErasureCommitment(encodedBlobs.ErasureCommitment)
		if err != nil {
			s.logger.Error("[signer] failed to encode wire erasure commitment", "batch", signInfo.ts, "error", err)
			return err
		}
		msg, err := getHashFromWire(dataRoot, signInfo.epoch, signInfo.quorumId, wireCommitment)
		if err != nil {
			s.logger.Error("[signer] failed to get hash for batch", "batch", signInfo.ts, "error", err)
			if signInfo.reties < s.MaxNumRetriesSign {
				s.mu.Lock()
				defer s.mu.Unlock()

				signInfo.reties += 1
				s.pendingBatchesToSign = append(s.pendingBatchesToSign, signInfo)
			} else {
				_ = s.handleFailure(ctx, signInfo.batch.BlobMetadata, FailAggregateSignatures)
				s.EncodingStreamer.RemoveBatchingStatus(signInfo.ts)
			}
			return err
		}

		messages[blobIdx] = msg
	}

	aggSigs := make([]*core.Signature, blobSize)
	aggPubKeys := make([]*core.G2Point, blobSize)

	signatureCounts := make([]int, blobSize)
	quorumBitmap := make([][]byte, blobSize)

	for i := 0; i < signerCounter; i++ {
		recv := <-update
		signerAddress := recv.signer
		signer := signInfo.signers[signerAddress]
		signatures := recv.signatures

		if recv.Err != nil {
			s.logger.Warn("[signer] error returned from messageChan", "socket", signer.Socket, "err", recv.Err)
			continue
		}

		s.logger.Debug("[signer] received signature from signer", "address", signer.Signer, "socket", signer.Socket, "signature size", len(signatures))
		for blobIdx, sig := range signatures {
			message := messages[blobIdx]
			weight := len(signer.sliceIndexes)
			if weight == 0 {
				continue
			}

			// Verify Signature
			ok := sig.Verify(signer.PkG2, message)
			if !ok {
				s.logger.Error("[signer] signature is not valid", "pubkey", hexutil.Encode(signer.PkG2.Serialize()))
				continue
			}

			weightedSig := scaleG1Point(sig.G1Point, weight)
			weightedPkG2 := scaleG2Point(signer.PkG2, weight)

			if aggSigs[blobIdx] == nil {
				aggSigs[blobIdx] = &core.Signature{G1Point: weightedSig}
				aggPubKeys[blobIdx] = weightedPkG2

				signatureCounts[blobIdx] = 0

				sliceSize := len(signInfo.batch.EncodedBlobs[blobIdx].EncodedSlice)
				bitmapLen := sliceSize / 8
				if sliceSize%8 != 0 {
					bitmapLen++
				}
				quorumBitmap[blobIdx] = make([]byte, bitmapLen)
			} else {
				aggSigs[blobIdx].Add(weightedSig)
				aggPubKeys[blobIdx].Add(weightedPkG2)
			}

			signatureCounts[blobIdx]++

			for _, sliceIdx := range signer.sliceIndexes {
				slot := sliceIdx / 8
				offset := sliceIdx % 8
				quorumBitmap[blobIdx][slot] |= 1 << offset
			}
		}
	}

	threshold := int(math.Ceil(float64(signerCounter) * 2 / 3))
	valid := true
	rootSubmissions := make([]*core.CommitRootSubmission, 0)
	for blobIdx, sig := range aggSigs {
		if signatureCounts[blobIdx] < threshold {
			valid = false
			break
		}

		rootSubmissions = append(rootSubmissions, &core.CommitRootSubmission{
			DataRoot:          storageRoots[blobIdx],
			ErasureCommitment: erasureCommitments[blobIdx],
			Epoch:             signInfo.epoch,
			QuorumId:          signInfo.quorumId,
			QuorumBitmap:      quorumBitmap[blobIdx],
			AggPkG2:           aggPubKeys[blobIdx],
			AggSigs:           sig,
		})
	}

	if valid {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.pendingSubmissions[signInfo.ts] = &BatchCommitRootSubmission{
			submissions: rootSubmissions,
			headerHash:  signInfo.headerHash,
			batch:       signInfo.batch,
			ts:          signInfo.ts,
			proofs:      signInfo.proofs,
		}
		s.signedBlobSize += uint64(len(signInfo.batch.EncodedBlobs))
		s.logger.Debug("[signer] get aggregate signature for batch", "ts", signInfo.ts)
		s.metrics.UpdateSignedBlobs(len(s.pendingSubmissions), s.signedBlobSize)

		if s.SignatureSizeNotifier.threshold > 0 && s.signedBlobSize > s.SignatureSizeNotifier.threshold {
			s.SignatureSizeNotifier.mu.Lock()

			if s.SignatureSizeNotifier.active {
				s.logger.Info("[signer] signed size threshold reached", "size", s.signedBlobSize)

				s.SignatureSizeNotifier.Notify <- struct{}{}
				s.SignatureSizeNotifier.active = false
			}
			s.SignatureSizeNotifier.mu.Unlock()
		}
	} else {
		if signInfo.reties < s.MaxNumRetriesSign {
			s.mu.Lock()
			defer s.mu.Unlock()

			signInfo.reties += 1
			s.pendingBatchesToSign = append(s.pendingBatchesToSign, signInfo)
			s.logger.Warn("[signer] retry signing", "retries", signInfo.reties)
		} else {
			_ = s.handleFailure(ctx, signInfo.batch.BlobMetadata, FailAggregateSignatures)

			for _, metadata := range signInfo.batch.BlobMetadata {
				meta, err := s.blobStore.GetBlobMetadata(ctx, metadata.GetBlobKey())
				if err != nil {
					s.logger.Error("[signer] failed to get blob metadata", "key", metadata.GetBlobKey(), "err", err)
				} else {
					if meta.BlobStatus == disperser.Failed {
						s.logger.Info("[signer] signing blob reach max retries", "key", metadata.GetBlobKey())
						s.EncodingStreamer.RemoveEncodedBlob(metadata)
					}
				}
			}

			s.EncodingStreamer.RemoveBatchingStatus(signInfo.ts)
			return errors.New("failed aggregate signatures")
		}
	}

	return nil
}

func (s *SliceSigner) GetCommitRootSubmissionBatch() ([]*BatchCommitRootSubmission, uint64, error) {
	ts := uint64(time.Now().Nanosecond())

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingSubmissions) == 0 {
		return nil, ts, errNoSignedResults
	}

	// Reset the notifier
	s.SignatureSizeNotifier.mu.Lock()
	s.SignatureSizeNotifier.active = true
	s.SignatureSizeNotifier.mu.Unlock()

	fetched := make([]*BatchCommitRootSubmission, 0)
	if _, ok := s.signedBatches[ts]; !ok {
		s.signedBatches[ts] = make([]uint64, 0)
	}

	blobSize := 0
	batchSize := 0
	for id, signedResult := range s.pendingSubmissions {
		if _, ok := s.signedBatching[id]; !ok {
			fetched = append(fetched, signedResult)
			s.signedBatching[id] = ts
			s.signedBatches[ts] = append(s.signedBatches[ts], id)

			blobSize += len(signedResult.submissions)

			if s.SignedBatchSize != 0 && batchSize > int(s.SignedBatchSize) {
				break
			}
		}
	}

	if len(fetched) == 0 {
		return nil, ts, errNoSignedResults
	}

	s.logger.Trace("[signer] consumed signed results", "fetched", len(fetched), "blob size", blobSize)
	return fetched, ts, nil
}

func (s *SliceSigner) RemoveSignedBlob(ts uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.pendingSubmissions[ts]
	if !ok {
		return
	}

	s.signedBlobSize -= uint64(len(s.pendingSubmissions[ts].batch.EncodedBlobs))
	delete(s.pendingSubmissions, ts)
	// remove from batching status
	delete(s.signedBatching, ts)
}

func (s *SliceSigner) RemoveBatchingStatus(ts uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if batch, ok := s.signedBatches[ts]; ok {
		for _, id := range batch {
			delete(s.signedBatching, id)
		}
	}
	delete(s.signedBatches, ts)
}

func wireFormatErasureCommitment(p *core.G1Point) ([]byte, error) {
	return core.WireFormatErasureCommitment(p)
}

func contractG2PointToGnark(p da_signers.BN254G2Point) *core.G2Point {
	pubkeyG2 := new(bn254.G2Affine)
	// BN254.sol encodes Fp2 as X[1] + X[0]*i; gnark uses A0 + A1*u (A0 real, A1 imag).
	pubkeyG2.X.A0.SetBigInt(p.X[1])
	pubkeyG2.X.A1.SetBigInt(p.X[0])
	pubkeyG2.Y.A0.SetBigInt(p.Y[1])
	pubkeyG2.Y.A1.SetBigInt(p.Y[0])
	return &core.G2Point{G2Affine: pubkeyG2}
}

func contractU256BytesFromWireCoord(wireCoord []byte) []byte {
	return ethmath.U256Bytes(core.U256FromLittleEndianBytes(wireCoord))
}

func getHashFromWire(dataRoot [32]byte, epoch, quorumId *big.Int, wireCommitment []byte) ([32]byte, error) {
	if len(wireCommitment) != fp.Bytes*2 {
		return [32]byte{}, fmt.Errorf("invalid wire erasure commitment length: %d", len(wireCommitment))
	}
	var packed []byte
	packed = append(packed, dataRoot[:]...)
	packed = append(packed, ethmath.U256Bytes(epoch)...)
	packed = append(packed, ethmath.U256Bytes(quorumId)...)
	packed = append(packed, contractU256BytesFromWireCoord(wireCommitment[:fp.Bytes])...)
	packed = append(packed, contractU256BytesFromWireCoord(wireCommitment[fp.Bytes:])...)
	return crypto.Keccak256Hash(packed), nil
}

func getHash(dataRoot [32]byte, epoch, quorumId *big.Int, erasureCommitment *core.G1Point) ([32]byte, error) {
	wireCommitment, err := wireFormatErasureCommitment(erasureCommitment)
	if err != nil {
		return [32]byte{}, err
	}
	return getHashFromWire(dataRoot, epoch, quorumId, wireCommitment)
}

func scaleG1Point(p *core.G1Point, weight int) *core.G1Point {
	if weight <= 1 {
		return p.Clone()
	}
	scaled := new(bn254.G1Affine).ScalarMultiplication(p.G1Affine, big.NewInt(int64(weight)))
	return &core.G1Point{G1Affine: scaled}
}

func scaleG2Point(p *core.G2Point, weight int) *core.G2Point {
	if weight <= 1 {
		return p.Clone()
	}
	scaled := new(bn254.G2Affine).ScalarMultiplication(p.G2Affine, big.NewInt(int64(weight)))
	return &core.G2Point{G2Affine: scaled}
}
