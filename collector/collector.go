package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/castai/image-analyzer"
	"github.com/castai/image-analyzer/blobscache"
	"github.com/castai/image-analyzer/image"
	"github.com/castai/image-analyzer/image/hostfs"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	// Import all registered analyzers.
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/buildinfo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/executable"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/c/conan"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/deps"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/gradle"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/npm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pnpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/yarn"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/packaging"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pipenv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/poetry"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/gemspec"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/mariner"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/release"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"

	_ "github.com/castai/image-analyzer/analyzer/pkg/apk"
	_ "github.com/castai/image-analyzer/analyzer/pkg/dpkg"
	_ "github.com/castai/image-analyzer/analyzer/pkg/rpm"
)

func New(log logrus.FieldLogger, cfg image_analyzer.Config, cache blobscache.Client, hostfsConfig *hostfs.ContainerdHostFSConfig) *Collector {
	return &Collector{
		log:          log,
		cfg:          cfg,
		cache:        cache,
		hostFsConfig: hostfsConfig,
	}
}

type Collector struct {
	log          logrus.FieldLogger
	cfg          image_analyzer.Config
	cache        blobscache.Client
	hostFsConfig *hostfs.ContainerdHostFSConfig
}

type ImageInfo struct {
	ID   string
	Name string
}

func (c *Collector) Collect(ctx context.Context) error {
	img, cleanup, err := c.getImage(ctx)
	if err != nil {
		return fmt.Errorf("getting image: %w", err)
	}
	defer cleanup()

	artifact, err := image.NewArtifact(img, c.log, c.cache, image.ArtifactOption{
		Offline: true,
		Slow:    c.cfg.SlowMode, // Slow mode limits concurrency and uses tmp files
		DisabledAnalyzers: []analyzer.Type{
			analyzer.TypeLicenseFile,
			analyzer.TypeDpkgLicense,
			analyzer.TypeJSON,
			analyzer.TypeHelm,
		},
	})
	if err != nil {
		return err
	}

	arRef, err := artifact.Inspect(ctx)
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("extract manifest: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("extract manifest digest: %w", err)
	}

	metadata := &image_analyzer.ImageMetadata{
		ImageName:    c.cfg.ImageName,
		ImageID:      c.cfg.ImageID,
		Architecture: arRef.ArtifactInfo.Architecture,
		ImageDigest:  digest.String(),
		ResourceIDs:  strings.Split(c.cfg.ResourceIDs, ","),
		BlobsInfo:    arRef.BlobsInfo,
		ConfigFile:   arRef.ConfigFile,
		Manifest:     manifest,
		OsInfo: &image_analyzer.OsInfo{
			ArtifactInfo: arRef.ArtifactInfo,
			OS:           arRef.OsInfo,
		},
	}

	if index := img.Index(); index != nil {
		metadata.Index = index
	}

	if err := backoff.RetryNotify(func() error {
		return c.sendResult(ctx, metadata)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3), func(err error, duration time.Duration) {
		if err != nil {
			c.log.Errorf("sending result: %v", err)
		}
	}); err != nil {
		return err
	}

	return nil
}

func (c *Collector) getImage(ctx context.Context) (image.ImageWithIndex, func(), error) {
	imgRef, err := name.ParseReference(c.cfg.ImageName)
	if err != nil {
		return nil, nil, err
	}
	if c.cfg.Mode == image_analyzer.ModeRemote {
		opts := image.DockerOption{}
		if c.cfg.ImagePullSecret != "" {
			configData, err := image_analyzer.ReadImagePullSecret(os.DirFS(image_analyzer.SecretMountPath))
			if err != nil {
				return nil, nil, fmt.Errorf("reading image pull secret: %w", err)
			}
			cfg := image.DockerConfig{}
			if err := json.Unmarshal(configData, &cfg); err != nil {
				return nil, nil, fmt.Errorf("parsing image pull secret: %w", err)
			}
			if auth, ok := cfg.Auths[imgRef.Context().Registry.Name()]; ok {
				opts.UserName = auth.Username
				opts.Password = auth.Password
				opts.RegistryToken = auth.Token
			}
			if auth, ok := cfg.Auths[image.NamespacedRegistry(imgRef)]; ok {
				opts.UserName = auth.Username
				opts.Password = auth.Password
				opts.RegistryToken = auth.Token
			}
			if auth, ok := cfg.Auths[fmt.Sprintf("%s/%s", imgRef.Context().RegistryStr(), imgRef.Context().RepositoryStr())]; ok {
				opts.UserName = auth.Username
				opts.Password = auth.Password
				opts.RegistryToken = auth.Token
			}
		} else if c.cfg.DockerOptionPath != "" {
			optsData, err := os.ReadFile(c.cfg.DockerOptionPath)
			if err != nil {
				return nil, nil, fmt.Errorf("reading docker options file: %w", err)
			}
			if err := yaml.Unmarshal(optsData, &opts); err != nil {
				return nil, nil, fmt.Errorf("unmarshaling docker options file: %w", err)
			}
		}
		img, err := image.NewFromRemote(ctx, c.cfg.ImageName, opts)
		return img, func() {}, err
	}

	if c.cfg.Runtime == image_analyzer.RuntimeContainerd {
		if c.cfg.Mode == image_analyzer.ModeDaemon {
			return image.NewFromContainerdDaemon(ctx, c.cfg.ImageName)
		}
		if c.cfg.Mode == image_analyzer.ModeHostFS {
			return image.NewFromContainerdHostFS(c.cfg.ImageID, *c.hostFsConfig)
		}
	}

	if c.cfg.Runtime == image_analyzer.RuntimeDocker {
		if c.cfg.Mode == image_analyzer.ModeTarArchive {
			return image.NewFromDockerDaemonTarFile(c.cfg.ImageName, c.cfg.ImageLocalTarPath, imgRef)
		}
		if c.cfg.Mode == image_analyzer.ModeDaemon {
			return image.NewFromDockerDaemon(c.cfg.ImageName, imgRef)
		}
	}

	return nil, nil, fmt.Errorf("unknown mode %q", c.cfg.Mode)
}

func (c *Collector) sendResult(ctx context.Context, report *image_analyzer.ImageMetadata) error {
	client := http.Client{Timeout: 10 * time.Second}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ApiURL+"/v1/image-scan/report", bytes.NewBuffer(reportBytes))
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if st := resp.StatusCode; st != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected status %d, got %d, url=%s: %v", http.StatusOK, st, req.URL.String(), string(errMsg))
	}
	return nil
}