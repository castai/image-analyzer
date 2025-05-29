package hostfs

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func TestContainerdImage(t *testing.T) {
	tests := []struct {
		name string
		hash v1.Hash
	}{
		{
			name: "find by index digest",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "211a3be9e15e1e4ccd75220aa776d92e06235552351464db2daf043bd30a0ac0",
			},
		},
		{
			name: "find by manifest digest",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "c3c447d49bb140a121311afd8d922eef160bfd63872fdb809ae89fdcf27bee50",
			},
		},
		{
			name: "find by config file digest",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "412c5a9fed875c1ce63f2dba535353162c9760c07379def9ac87cb0201b532de",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			img, err := NewContainerdImage(tt.hash, ContainerdHostFSConfig{
				Platform: v1.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
				ContentDir: "./testdata/containerd_content",
			})
			r.NoError(err)
			layers, err := img.Layers()
			r.NoError(err)
			r.Len(layers, 2)
			manifest, err := img.Manifest()
			r.NoError(err)
			r.Len(manifest.Layers, 2)
			config, err := img.ConfigFile()
			r.NoError(err)
			r.Len(config.RootFS.DiffIDs, 2)
			manifestDigest, err := img.Digest()
			r.NoError(err)
			r.Equal(tests[1].hash, manifestDigest)
		})
	}
}

func TestContainerdImageWithIndex(t *testing.T) {
	r := require.New(t)
	hash := v1.Hash{
		Algorithm: "sha256",
		Hex:       "211a3be9e15e1e4ccd75220aa776d92e06235552351464db2daf043bd30a0ac0",
	}
	img, err := NewContainerdImage(hash, ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: "./testdata/containerd_content",
	})
	r.NoError(err)

	index, err := img.IndexManifest()
	r.NoError(err)
	r.NotNil(index)

	indexDigest, err := img.IndexDigest()
	r.NoError(err)
	r.Equal(hash, indexDigest)

	manifest, err := img.Manifest()
	r.NoError(err)
	r.NotNil(manifest)
	r.Len(manifest.Layers, 2)
}
