package image

import (
	"github.com/castai/image-analyzer/image/hostfs"
	"github.com/castai/image-analyzer/image/types"
)

func NewFromContainerdHostFS(imageID string, config hostfs.ContainerdHostFSConfig) (types.ImageWithIndex, func(), error) {
	hash, err := hostfs.NewImageHash(imageID)
	if err != nil {
		return nil, nil, err
	}
	img, err := hostfs.NewContainerdImage(hash, config)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		ImageWithIndex: img,
		name:           hash.Hex,
	}, func() {}, nil
}

type extendedBlobImage struct {
	types.ImageWithIndex
	name string
}

func (b extendedBlobImage) Name() string {
	return b.name
}
