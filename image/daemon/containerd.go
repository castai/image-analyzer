// Trivy
// Copyright 2019-2020 Aqua Security Software Ltd.
// This product includes software developed by Aqua Security (https://aquasec.com).
//
// Adapted from https://github.com/aquasecurity/trivy and changed default containerd namespace to k8s.io

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	itypes "github.com/castai/image-analyzer/image/types"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	api "github.com/docker/docker/api/types"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"
)

const (
	defaultContainerdSocket    = "/run/containerd/containerd.sock"
	defaultContainerdNamespace = "k8s.io"
)

func imageWriter(c *client.Client, img client.Image) imageSave {
	return func(ctx context.Context, ref []string) (io.ReadCloser, error) {
		if len(ref) < 1 {
			return nil, errors.New("no image reference")
		}
		imgOpts := archive.WithImage(c.ImageService(), ref[0])
		manifestOpts := archive.WithManifest(img.Target())
		platOpts := archive.WithPlatform(platforms.DefaultStrict())
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(archive.Export(ctx, c.ContentStore(), pw, imgOpts, manifestOpts, platOpts))
		}()
		return pr, nil
	}
}

// ContainerdImage implements v1.Image
func ContainerdImage(ctx context.Context, imageName string) (itypes.ImageWithIndex, func(), error) {
	cleanup := func() {}

	addr := os.Getenv("CONTAINERD_ADDRESS")
	if addr == "" {
		// TODO: support rootless
		addr = defaultContainerdSocket
	}

	if _, err := os.Stat(addr); errors.Is(err, os.ErrNotExist) {
		return nil, cleanup, fmt.Errorf("containerd socket not found: %s", addr)
	}

	// Parse the image name
	ref, err := reference.ParseDockerRef(imageName)
	if err != nil {
		return nil, cleanup, fmt.Errorf("parse error: %w", err)
	}

	c, err := client.New(addr)
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to initialize a containerd client: %w", err)
	}

	// Need to specify a namespace
	ctx = namespaces.WithNamespace(ctx, defaultContainerdNamespace)

	img, err := c.GetImage(ctx, ref.String())
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to get %s: %w", imageName, err)
	}

	f, err := os.CreateTemp("", "fanal-containerd-*")
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	insp, history, err := inspect(ctx, img, ref)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect error: %w", err)
	}

	return &image{
		opener:  imageOpener(ctx, ref.String(), f, imageWriter(c, img)),
		inspect: insp,
		history: history,
	}, cleanup, nil
}

// readImageConfig reads the config spec (`application/vnd.oci.image.config.v1+json`) for img.platform from content store.
// ported from https://github.com/containerd/nerdctl/blob/7dfbaa2122628921febeb097e7a8a86074dc931d/pkg/imgutil/imgutil.go#L377-L393
func readImageConfig(ctx context.Context, img client.Image) (ocispec.Image, ocispec.Descriptor, error) {
	var config ocispec.Image

	configDesc, err := img.Config(ctx) // aware of img.platform
	if err != nil {
		return config, configDesc, err
	}
	p, err := content.ReadBlob(ctx, img.ContentStore(), configDesc)
	if err != nil {
		return config, configDesc, err
	}
	if err = json.Unmarshal(p, &config); err != nil {
		return config, configDesc, err
	}
	return config, configDesc, nil
}

// ported from https://github.com/containerd/nerdctl/blob/d110fea18018f13c3f798fa6565e482f3ff03591/pkg/inspecttypes/dockercompat/dockercompat.go#L279-L321
func inspect(ctx context.Context, img client.Image, ref reference.Named) (api.ImageInspect, []v1.History, error) {
	var tag string
	if tagged, ok := ref.(reference.Tagged); ok {
		tag = tagged.Tag()
	}
	repository := reference.FamiliarName(ref)

	imgConfig, imgConfigDesc, err := readImageConfig(ctx, img)
	if err != nil {
		return api.ImageInspect{}, nil, err
	}

	var lastHistory ocispec.History
	var lastCreated string
	if len(imgConfig.History) > 0 {
		lastHistory = imgConfig.History[len(imgConfig.History)-1]
		lastCreated = lastHistory.Created.Format(time.RFC3339Nano)
	}

	var history []v1.History
	for _, h := range imgConfig.History {
		hist := v1.History{
			Author:     h.Author,
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		}

		if h.Created != nil {
			hist.Created = v1.Time{Time: *h.Created}
		}

		history = append(history, hist)
	}

	return api.ImageInspect{
		ID:          imgConfigDesc.Digest.String(),
		RepoTags:    []string{fmt.Sprintf("%s:%s", repository, tag)},
		RepoDigests: []string{fmt.Sprintf("%s@%s", repository, img.Target().Digest)},
		Comment:     lastHistory.Comment,
		Created:     lastCreated,
		Author:      lastHistory.Author,
		Config: &dockerspec.DockerOCIImageConfig{
			ImageConfig: imgConfig.Config,
		},
		Architecture: imgConfig.Architecture,
		Os:           imgConfig.OS,
		RootFS: api.RootFS{
			Type: imgConfig.RootFS.Type,
			Layers: lo.Map(imgConfig.RootFS.DiffIDs, func(d digest.Digest, _ int) string {
				return d.String()
			}),
		},
	}, history, nil
}
