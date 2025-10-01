package image

import (
	"context"

	"github.com/castai/image-analyzer/image/daemon"
	itypes "github.com/castai/image-analyzer/image/types"

	"github.com/google/go-containerregistry/pkg/name"
)

func NewFromContainerdDaemon(ctx context.Context, imageName string) (itypes.ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.ContainerdImage(ctx, imageName)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		ImageWithIndex: img,
		name:           imageName,
	}, cleanup, nil
}

func NewFromDockerDaemon(imageName string, ref name.Reference) (itypes.ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		ImageWithIndex: img,
		name:           imageName,
	}, cleanup, nil
}

func NewFromDockerDaemonTarFile(imageName, localTarPath string, ref name.Reference) (itypes.ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.DockerTarImage(ref, localTarPath)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		ImageWithIndex: img,
		name:           imageName,
	}, cleanup, nil
}

type daemonImage struct {
	itypes.ImageWithIndex
	name string
}

func (d daemonImage) Name() string {
	return d.name
}
