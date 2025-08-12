package image

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
)

type DockerConfig struct {
	Auths map[string]authn.AuthConfig `json:"auths"`
}

// NewFromRemote pulls using dockerAuth if provided (via authn.FromConfig).
// Otherwise it tries the Trivy cloud-provider token fallback (ECR/GCR/ACR).
// If neither is available, it pulls anonymously.
func NewFromRemote(
	ctx context.Context,
	log logrus.FieldLogger,
	imageName string,
	option types.ImageOptions,
	dockerAuth *authn.AuthConfig, // optional: raw docker auth block
) (ImageWithIndex, error) {
	var nameOpts []name.Option
	if option.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the image name: %w", err)
	}

	img, err := tryRemote(ctx, log, imageName, ref, option, dockerAuth)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func tryRemote(
	ctx context.Context,
	log logrus.FieldLogger,
	imageName string,
	ref name.Reference,
	option types.ImageOptions,
	dockerAuth *authn.AuthConfig,
) (ImageWithIndex, error) {
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
	}

	// honor "insecure" — allow HTTP or skip TLS verification
	if option.RegistryOptions.Insecure {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	// Auth selection:
	if dockerAuth != nil {
		log.Info("using docker config authentication to pull an image")
		remoteOpts = append(remoteOpts, remote.WithAuth(authn.FromConfig(*dockerAuth)))
	} else {
		log.Info("no docker auth provided; trying cloud-provider/bearer/anonymous")
		domain := ref.Context().RegistryStr()

		// In theory might be used when the workloads don’t use a pull secret because the cluster has node or pod identity-based
		// registry access configured (e.g., ECR IAM roles, GKE Workload Identity, AKS Managed Identity).
		if auth := registry.GetToken(ctx, domain, option.RegistryOptions); auth.Username != "" || auth.Password != "" {
			log.Info("using cloud provider registry token to pull an image")
			remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
		} else if tok := strings.TrimSpace(option.RegistryOptions.RegistryToken); tok != "" {
			log.Info("using bearer token to pull an image")
			remoteOpts = append(remoteOpts, remote.WithAuth(&authn.Bearer{Token: tok}))
		} else {
			log.Info("pulling anonymously (no auth)")
		}
	}

	// honor requested platform
	if platform := option.RegistryOptions.Platform.Platform; platform != nil {
		remoteOpts = append(remoteOpts, remote.WithPlatform(*platform))
	}

	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, err
	}

	img, err := desc.Image()
	if err != nil {
		return nil, err
	}

	// Return v1.Image if the image is found in Docker Registry
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, nil
}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *remote.Descriptor
	v1.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	return ID(img)
}

func (img remoteImage) LayerIDs() ([]string, error) {
	return LayerIDs(img)
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

func (img remoteImage) Index() *v1.IndexManifest {
	return nil
}

type implicitReference struct {
	ref name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()

	// Default registry
	if reg != name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}

	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}
