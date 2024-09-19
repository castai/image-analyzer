package analyzer

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
	img, err := image.NewFromRemote(ctx, log, digest, types.ImageOptions{})
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

type mockBlockCache struct{}

func (mockBlockCache) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (mockBlockCache) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, ErrCacheNotFound
}
