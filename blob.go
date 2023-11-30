package analyzer

import (
	"github.com/castai/image-analyzer/image"
	"github.com/castai/image-analyzer/image/hostfs"
)

func NewFromContainerdHostFS(imageID string, config hostfs.ContainerdHostFSConfig) (image.ImageWithIndex, func(), error) {
	hash, err := hostfs.NewImageHash(imageID)
	if err != nil {
		return nil, nil, err
	}
	img, err := hostfs.NewContainerdImage(hash, config)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		Image: img,
		name:  hash.Hex,
	}, func() {}, nil
}

type extendedBlobImage struct {
	hostfs.Image
	name string
}

func (b extendedBlobImage) Name() string {
	return b.name
}

func (b extendedBlobImage) ID() (string, error) {
	return image.ID(b)
}

func (b extendedBlobImage) LayerIDs() ([]string, error) {
	return image.LayerIDs(b)
}
