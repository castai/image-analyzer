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
)

type DockerConfig struct {
	Auths map[string]RegistryAuth `json:"auths"`
}

type RegistryAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"auth"`
}

func NewFromRemote(ctx context.Context, imageName string, option types.ImageOptions) (ImageWithIndex, error) {
	var nameOpts []name.Option
	if option.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the image name: %w", err)
	}

	img, err := tryRemote(ctx, imageName, ref, option)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func tryRemote(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (ImageWithIndex, error) {
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
	}
	if option.RegistryOptions.Insecure {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	// Username/Password based auth.
	for _, cred := range option.RegistryOptions.Credentials {
		remoteOpts = append(remoteOpts, remote.WithAuth(&authn.Basic{
			Username: cred.Username,
			Password: cred.Password,
		}))
	}

	domain := ref.Context().RegistryStr()
	auth := registry.GetToken(ctx, domain, option.RegistryOptions)
	if auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
	} else if option.RegistryOptions.RegistryToken != "" {
		bearer := authn.Bearer{Token: option.RegistryOptions.RegistryToken}
		remoteOpts = append(remoteOpts, remote.WithAuth(&bearer))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

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
