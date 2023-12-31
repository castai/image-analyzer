package image

import (
	"context"

	"github.com/castai/image-analyzer/image/daemon"
	"github.com/google/go-containerregistry/pkg/name"
)

func NewFromContainerdDaemon(ctx context.Context, imageName string) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.ContainerdImage(ctx, imageName)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemon(imageName string, ref name.Reference) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemonTarFile(imageName, localTarPath string, ref name.Reference) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon.DockerTarImage(ref, localTarPath)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

type daemonImage struct {
	daemon.Image
	name string
}

func (d daemonImage) Name() string {
	return d.name
}

func (d daemonImage) ID() (string, error) {
	return ID(d)
}

func (d daemonImage) LayerIDs() ([]string, error) {
	return LayerIDs(d)
}
