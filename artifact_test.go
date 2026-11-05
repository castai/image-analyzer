package analyzer

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/image-analyzer/image"
)

func TestArtifact(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	digest := "alpine@sha256:60eda2a7bc29a54fe6beae0d72312ea995eb3b8387535e8dbf6767fd1b765d34" // linux/amd64 digest
	img, err := image.NewFromRemote(ctx, log, digest, types.ImageOptions{}, nil)
	r.NoError(err)

	artifact, err := NewArtifact(img, log, mockBlockCache{}, ArtifactOption{
		Offline:  true,
		Parallel: 1,
	})
	r.NoError(err)

	ref, err := artifact.Inspect(ctx)
	r.NoError(err)
	r.NotNil(ref)
	r.NotNil(ref.BlobsInfo)
	r.Len(ref.BlobsInfo, 1)
	r.Len(ref.BlobsInfo[0].PackageInfos, 1)
	r.Len(ref.BlobsInfo[0].PackageInfos[0].Packages, 15)

	r.NotNil(ref.ConfigFile)
	r.Equal("amd64", ref.ConfigFile.Architecture)
	r.Equal("linux", ref.ConfigFile.OS)

	r.NotNil(ref.ArtifactInfo)
	r.Equal("amd64", ref.ArtifactInfo.Architecture)
	r.Equal("linux", ref.ArtifactInfo.OS)

	r.NotNil(ref.OsInfo)
	r.Equal("alpine", string(ref.OsInfo.Family))
}

func TestArtifactClosesLayerReaders(t *testing.T) {
	r := require.New(t)

	base, err := random.Image(1024, 6)
	r.NoError(err)
	// The fake refuses a fifth open on purpose, so a regression shows up as an error instead of a hung test.
	// This mirrors the per-image limit of 4 open layer readers in go-containerregistry since v0.21.6.
	img := &limitedOpenImage{Image: base, maxOpen: 4}

	artifact, err := NewArtifact(img, logrus.New(), mockBlockCache{}, ArtifactOption{
		Offline:  true,
		Parallel: 1,
	})
	r.NoError(err)

	ref, err := artifact.Inspect(context.Background())
	r.NoError(err)
	r.Len(ref.BlobsInfo, 6)
	r.Equal(0, img.openReaders())
}

// limitedOpenImage fails to open a layer when maxOpen layer readers are already open.
type limitedOpenImage struct {
	v1.Image
	maxOpen int

	mu   sync.Mutex
	open int
}

func (i *limitedOpenImage) Name() string { return "test" }

func (i *limitedOpenImage) ID() (string, error) {
	h, err := i.ConfigName()
	return h.String(), err
}

func (i *limitedOpenImage) RepoTags() []string { return nil }

func (i *limitedOpenImage) RepoDigests() []string { return nil }

func (i *limitedOpenImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	l, err := i.Image.LayerByDiffID(h)
	if err != nil {
		return nil, err
	}
	return &limitedOpenLayer{Layer: l, img: i}, nil
}

func (i *limitedOpenImage) openReaders() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.open
}

type limitedOpenLayer struct {
	v1.Layer
	img *limitedOpenImage
}

func (l *limitedOpenLayer) Uncompressed() (io.ReadCloser, error) {
	l.img.mu.Lock()
	defer l.img.mu.Unlock()
	if l.img.open >= l.img.maxOpen {
		return nil, errors.New("too many open layer readers")
	}
	rc, err := l.Layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	l.img.open++
	return &trackedReadCloser{ReadCloser: rc, img: l.img}, nil
}

type trackedReadCloser struct {
	io.ReadCloser
	img  *limitedOpenImage
	once sync.Once
}

func (c *trackedReadCloser) Close() error {
	c.once.Do(func() {
		c.img.mu.Lock()
		c.img.open--
		c.img.mu.Unlock()
	})
	return c.ReadCloser.Close()
}

type mockBlockCache struct{}

func (mockBlockCache) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (mockBlockCache) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, ErrCacheNotFound
}
