// Trivy
// Copyright 2019-2020 Aqua Security Software Ltd.
// This product includes software developed by Aqua Security (https://aquasec.com).
//
// Adapted from https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/artifact/image/image.go in order to remove some checks and fix race conditions
// while scanning multiple images.

package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	_ "github.com/castai/image-analyzer/apk"
	_ "github.com/castai/image-analyzer/dpkg"
	_ "github.com/castai/image-analyzer/rpm"
)

// Artifact bundles image with the required dependencies to be able to scan it.
type Artifact struct {
	log            logrus.FieldLogger
	image          types.Image
	cache          CacheClient
	walker         walker.LayerTar
	analyzer       analyzer.AnalyzerGroup
	configAnalyzer analyzer.ConfigAnalyzerGroup
	handlerManager handler.Manager
	artifactOption artifact.Option
}

// ArtifactReference represents uncompressed image with its layers also uncompressed
type ArtifactReference struct {
	// BlobsInfo contains information about image layers
	BlobsInfo    []types.BlobInfo
	ConfigFile   *v1.ConfigFile
	ArtifactInfo *types.ArtifactInfo
	OsInfo       *types.OS
}

// ArtifactOption customizes scanning behavior
type ArtifactOption = artifact.Option

// CachedImage does not contain information about layers.
// Identified by ImageID in cache.
type CachedImage = types.ArtifactInfo

// CachedLayers are identified by diffID in cache.
type CachedLayers = map[string]types.BlobInfo

type layerHashes struct {
	// required to avoid calculation later
	compressed string
	// required for layer lookup in the cache
	uncompressed string
}

// NewArtifact bundles already pulled image with additional dependencies for scanning.
func NewArtifact(img types.Image, log logrus.FieldLogger, c CacheClient, opt ArtifactOption) (*Artifact, error) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:             opt.AnalyzerGroup,
		DisabledAnalyzers: opt.DisabledAnalyzers,
	})
	if err != nil {
		return nil, fmt.Errorf("create analyzer group: %w", err)
	}

	ca, err := analyzer.NewConfigAnalyzerGroup(analyzer.ConfigAnalyzerOptions{
		FilePatterns:         opt.FilePatterns,
		DisabledAnalyzers:    opt.DisabledAnalyzers,
		MisconfScannerOption: opt.MisconfScannerOption,
		SecretScannerOption:  opt.SecretScannerOption,
	})
	if err != nil {
		return nil, fmt.Errorf("create config analyzer group: %w", err)
	}

	return &Artifact{
		log:   log,
		image: img,
		cache: c,
		walker: walker.NewLayerTar(walker.Option{
			SkipFiles: opt.WalkerOption.SkipFiles,
			SkipDirs:  opt.WalkerOption.SkipDirs,
		}),
		analyzer:       a,
		configAnalyzer: ca,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (*ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return nil, fmt.Errorf("getting image ID: %w", err)
	}
	a.log.Debugf("image ID: %s", imageID)

	layers, err := a.image.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image's layers: %w", err)
	}

	layerIDs, err := getLayerHashes(layers)
	if err != nil {
		return nil, fmt.Errorf("getting layer's hashes: %w", err)
	}

	diffIDs := lo.Map(layerIDs, func(pair layerHashes, _ int) string { return pair.uncompressed })
	a.log.Debugf("diff IDs: %v", diffIDs)

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("getting image's config file: %w", err)
	}

	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	a.log.Debugf("base layer diff IDs: %v", baseDiffIDs)

	cachedLayers, err := a.getCachedLayers(ctx, diffIDs)
	if err != nil {
		return nil, fmt.Errorf("getting cached layers: %w", err)
	}

	missingLayerDiffIDs := lo.Filter(diffIDs, func(v string, _ int) bool {
		_, ok := cachedLayers[v]
		return !ok
	})
	a.log.Debugf("found %d cached layers, %d layers will be inspected", len(cachedLayers), len(missingLayerDiffIDs))
	a.log.Debugf("layers with the following diff IDs will be inspected: %v", missingLayerDiffIDs)

	blobsInfo, osInfo, err := a.inspectLayers(ctx, layerIDs, baseDiffIDs)
	if err != nil {
		return nil, fmt.Errorf("analyzing layers: %w", err)
	}

	artifactInfo, err := a.inspectImage(ctx, configFile, imageID, *osInfo)
	if err != nil {
		return nil, fmt.Errorf("analyzing image: %w", err)
	}

	return &ArtifactReference{
		BlobsInfo:    append(blobsInfo, lo.Values(cachedLayers)...),
		ConfigFile:   configFile,
		ArtifactInfo: artifactInfo,
		OsInfo:       osInfo,
	}, nil
}

func getLayerHashes(layers []v1.Layer) ([]layerHashes, error) {
	layerIDs := make([]layerHashes, 0, len(layers))
	for _, layer := range layers {
		compressedID, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("getting layer digest: %w", err)
		}

		uncompressedID, err := layer.DiffID()
		if err != nil {
			return nil, fmt.Errorf("getting layer diff ID: %w", err)
		}

		layerIDs = append(layerIDs, layerHashes{
			compressed:   compressedID.String(),
			uncompressed: uncompressedID.String(),
		})
	}

	return layerIDs, nil
}

func (a Artifact) getCachedImage(ctx context.Context, imageID string) (*CachedImage, error) {
	blobBytes, err := a.cache.GetBlob(ctx, imageID)
	if err != nil {
		return nil, ErrCacheNotFound
	}
	var res types.ArtifactInfo
	if err := json.Unmarshal(blobBytes, &res); err != nil {
		return nil, fmt.Errorf("unmarshalling image: %w", err)
	}
	return &res, nil
}

func (a Artifact) getCachedLayers(ctx context.Context, diffIDs []string) (CachedLayers, error) {
	blobs := CachedLayers{}
	for _, diffID := range diffIDs {
		blobBytes, err := a.cache.GetBlob(ctx, diffID)
		if err != nil && !errors.Is(err, ErrCacheNotFound) {
			continue
		}
		if len(blobBytes) > 0 {
			var blob types.BlobInfo
			if err := json.Unmarshal(blobBytes, &blob); err != nil {
				return nil, fmt.Errorf("unmarshalling layer: %w", err)
			}
			blobs[diffID] = blob
		}
	}
	return blobs, nil
}

func (a Artifact) putImageToCache(ctx context.Context, imageID string, image types.ArtifactInfo) error {
	infoBytes, err := json.Marshal(image)
	if err != nil {
		return fmt.Errorf("marshalling image: %w", err)
	}

	return a.cache.PutBlob(ctx, imageID, infoBytes)
}

func (a Artifact) putLayerToCache(ctx context.Context, diffID string, layer types.BlobInfo) error {
	layerBytes, err := json.Marshal(layer)
	if err != nil {
		return fmt.Errorf("marshalling layer: %w", err)
	}

	return a.cache.PutBlob(ctx, diffID, layerBytes)
}

func (Artifact) Clean(_ artifact.Reference) error {
	return nil
}

func (a Artifact) inspectLayers(ctx context.Context, layerIDs []layerHashes, baseLayerDiffIDs []string) ([]types.BlobInfo, *types.OS, error) {
	blobCh := make(chan types.BlobInfo)
	errCh := make(chan error)
	limit := semaphore.NewWeighted(int64(a.artifactOption.Parallel))

	var osFound types.OS

	go func() {
		for _, layerIdPair := range layerIDs {
			if err := limit.Acquire(ctx, 1); err != nil {
				errCh <- fmt.Errorf("acquiring semaphore: %w", err)
				return
			}

			go func(ctx context.Context, blobCh chan<- types.BlobInfo, errCh chan<- error, digest, diffID string) {
				defer limit.Release(1)

				// If it is a base layer, secret scanning should not be performed.
				var disabledAnalyzers []analyzer.Type
				if slices.Contains(baseLayerDiffIDs, diffID) {
					disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
				}

				layerInfo, err := a.inspectLayer(ctx, digest, diffID, disabledAnalyzers)
				if err != nil {
					errCh <- fmt.Errorf("analyzing layer with diff ID %s: %w", diffID, err)
					return
				}

				if err := a.putLayerToCache(ctx, diffID, layerInfo); err != nil {
					a.log.Warnf("putting layer blob to cache: %v", err)
				}

				if layerInfo.OS != (types.OS{}) {
					osFound = layerInfo.OS
				}
				blobCh <- layerInfo
			}(ctx, blobCh, errCh, layerIdPair.compressed, layerIdPair.uncompressed)
		}
	}()

	blobsInfo := make([]types.BlobInfo, 0, len(layerIDs))

	for range layerIDs {
		select {
		case blob := <-blobCh:
			blobsInfo = append(blobsInfo, blob)
		case err := <-errCh:
			return nil, nil, err
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	return blobsInfo, &osFound, nil
}

func (a Artifact) inspectLayer(ctx context.Context, digest, diffID string, disabled []analyzer.Type) (types.BlobInfo, error) {
	a.log.Debugf("analyzing layer with digest %q and diff ID %q", digest, diffID)

	layerReader, err := a.openUncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.NewWeighted(int64(a.artifactOption.Parallel))

	opaqueDirs, whiteoutFiles, err := a.walker.Walk(layerReader, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		return a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts)
	})
	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("walk error: %w", err)
	}

	wg.Wait()
	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:   types.BlobJSONSchemaVersion,
		Digest:          digest,
		DiffID:          diffID,
		OS:              result.OS,
		Repository:      result.Repository,
		PackageInfos:    result.PackageInfos,
		Applications:    result.Applications,
		Secrets:         result.Secrets,
		OpaqueDirs:      opaqueDirs,
		WhiteoutFiles:   whiteoutFiles,
		CustomResources: result.CustomResources,

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	// Call post handlers to modify blob info
	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, fmt.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) openUncompressedLayer(diffID string) (io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return nil, fmt.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return nil, fmt.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	return layer.Uncompressed()
}

func (a Artifact) inspectImage(ctx context.Context, cfg *v1.ConfigFile, imageID string, osFound types.OS) (*types.ArtifactInfo, error) {
	cachedImage, err := a.getCachedImage(ctx, imageID)
	if err == nil {
		return cachedImage, nil
	}

	pkgs := a.configAnalyzer.AnalyzeImageConfig(ctx, osFound, cfg)
	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    cfg.Architecture,
		Created:         cfg.Created.Time,
		DockerVersion:   cfg.DockerVersion,
		OS:              cfg.OS,
		HistoryPackages: pkgs.HistoryPackages,
	}

	if err := a.putImageToCache(ctx, imageID, info); err != nil {
		a.log.Warnf("putting image blob to cache: %v", err)
	}

	return &info, nil
}

// Guess layers in base image (call base layers).
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	var baseImageIndex int
	var foundNonEmpty bool
	for i := len(configFile.History) - 1; i >= 0; i-- {
		h := configFile.History[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}
