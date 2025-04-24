package analyzer

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

func TestSingleArchImageDigest(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	// image https://hub.docker.com/layers/kennethreitz/httpbin/latest/images/sha256-b138b9264903f46a43e1c750e07dc06f5d2a1bd5d51f37fb185bc608f61090dd
	imageToScan := "kennethreitz/httpbin:latest"
	img, err := image.NewFromRemote(ctx, log, imageToScan, types.ImageOptions{})
	r.NoError(err)

	// id
	id, err := img.ID()
	r.NoError(err)
	r.Equal("sha256:b138b9264903f46a43e1c750e07dc06f5d2a1bd5d51f37fb185bc608f61090dd", id)

	// config manifest digest
	manifest, err := img.Manifest()
	r.NoError(err)
	configDigest := manifest.Config.Digest.String()
	r.Equal("sha256:b138b9264903f46a43e1c750e07dc06f5d2a1bd5d51f37fb185bc608f61090dd", configDigest)

	// repo digest
	repoDigests := img.RepoDigests()
	r.Len(repoDigests, 1)
	r.Equal("kennethreitz/httpbin@sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b", repoDigests[0])

	// manifest digest
	manifestDigest, err := img.Digest()
	r.NoError(err)
	r.Equal("sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b", manifestDigest.String())
}

func TestMultiArchImageDigest(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	// image https://hub.docker.com/layers/library/clickhouse/25.3.2/images/sha256-968a846c076df76ad7da705517e7bafb962b1db615b2526c1f13995e2fa39781
	imageToScan := "clickhouse:25.3.2"

	t.Run("linux/amd64 variant", func(t *testing.T) {
		img, err := image.NewFromRemote(ctx, log, imageToScan, types.ImageOptions{
			RegistryOptions: types.RegistryOptions{
				Platform: types.Platform{
					Platform: &v1.Platform{
						OS:           "linux",
						Architecture: "amd64",
					},
				},
			},
		})
		r.NoError(err)

		// id
		id, err := img.ID()
		r.NoError(err)
		r.Equal("sha256:f2aafc8bcd7da81efe8c1ab85cb9fba3b9cab375dccf13c0e9236eb73383d75d", id)

		// config manifest digest
		manifest, err := img.Manifest()
		r.NoError(err)
		configDigest := manifest.Config.Digest.String()
		r.Equal("sha256:f2aafc8bcd7da81efe8c1ab85cb9fba3b9cab375dccf13c0e9236eb73383d75d", configDigest)

		// repo digest
		repoDigests := img.RepoDigests()
		r.Len(repoDigests, 1)
		r.Equal("clickhouse@sha256:968a846c076df76ad7da705517e7bafb962b1db615b2526c1f13995e2fa39781", repoDigests[0])

		// manifest digest
		manifestDigest, err := img.Digest()
		r.NoError(err)
		r.Equal("sha256:0c7dc14e63e6b5d5810d752ca28bb24c0fb6552971a19514d914bceac93f44e0", manifestDigest.String())
	})

	t.Run("linux/arm64/v8 variant", func(t *testing.T) {
		img, err := image.NewFromRemote(ctx, log, imageToScan, types.ImageOptions{
			RegistryOptions: types.RegistryOptions{
				Platform: types.Platform{
					Platform: &v1.Platform{
						OS:           "linux",
						Architecture: "arm64",
					},
				},
			},
		})
		r.NoError(err)

		// id
		id, err := img.ID()
		r.NoError(err)
		r.Equal("sha256:d0627f5fcf41e2bc0cb6f5be9dca139d3ffb54d5cd29d75f780a57e373bac720", id)

		// config manifest digest
		manifest, err := img.Manifest()
		r.NoError(err)
		configDigest := manifest.Config.Digest.String()
		r.Equal("sha256:d0627f5fcf41e2bc0cb6f5be9dca139d3ffb54d5cd29d75f780a57e373bac720", configDigest)

		// repo digest
		repoDigests := img.RepoDigests()
		r.Len(repoDigests, 1)
		r.Equal("clickhouse@sha256:968a846c076df76ad7da705517e7bafb962b1db615b2526c1f13995e2fa39781", repoDigests[0])

		// manifest digest
		manifestDigest, err := img.Digest()
		r.NoError(err)
		r.Equal("sha256:b2f8e72d0cb3159313521f04f9e1de12e401aa4cac97be63d75545f722d70be5", manifestDigest.String())
	})
}

type mockBlockCache struct{}

func (mockBlockCache) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (mockBlockCache) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, ErrCacheNotFound
}
