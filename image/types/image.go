package types

import (
	"errors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var ErrImageIndexNotFound = errors.New("image index not found")

type Image = types.Image

type ImageIndex interface {
	IndexDigest() (v1.Hash, error)
	IndexManifest() (*v1.IndexManifest, error)
}

type ImageWithIndex interface {
	Image
	ImageIndex
}
