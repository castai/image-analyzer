package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type miniManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fakeRegistry(t *testing.T, wantAuthPrefix string, omitCfg, omitLayer bool) *httptest.Server {
	t.Helper()

	cfg := []byte(`{}`)
	layer := []byte("layer")
	cfgDigest := sha256Digest(cfg)
	layerDigest := sha256Digest(layer)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("FAKE REGISTRY: %s %s Authorization=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))

		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
			return

		case strings.Contains(r.URL.Path, "/manifests/"):
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			if wantAuthPrefix != "" && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(wantAuthPrefix)) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="test",service="test",scope="repository:repo:pull"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var m miniManifest
			m.SchemaVersion = 2
			m.MediaType = "application/vnd.oci.image.manifest.v1+json"
			m.Config.MediaType = "application/vnd.oci.image.config.v1+json"
			m.Config.Size = int64(len(cfg))
			m.Config.Digest = cfgDigest
			m.Layers = []struct {
				MediaType string `json:"mediaType"`
				Size      int64  `json:"size"`
				Digest    string `json:"digest"`
			}{
				{"application/vnd.oci.image.layer.v1.tar", int64(len(layer)), layerDigest},
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(m)
			return

		case strings.Contains(r.URL.Path, "/blobs/"):
			switch {
			case strings.HasSuffix(r.URL.Path, cfgDigest):
				if omitCfg {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
				w.Write(cfg)
			case strings.HasSuffix(r.URL.Path, layerDigest):
				if omitLayer {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.oci.image.layer.v1.tar")
				w.Write(layer)
			default:
				http.NotFound(w, r)
			}
			return
		}
	})

	return httptest.NewServer(mux)
}

func TestNewFromRemote_AuthVariants(t *testing.T) {
	tests := []struct {
		name        string
		authCfg     *authn.AuthConfig
		wantAuth    string
		registryTok string
		credentials []types.Credential
		expectErr   bool
	}{
		{"basic_auth_field", &authn.AuthConfig{Auth: "dXNlcjpwYXNz"}, "Basic dXNlcjpwYXNz", "", nil, false},
		{"basic_user_pass", &authn.AuthConfig{Username: "user", Password: "pass"}, "Basic dXNlcjpwYXNz", "", nil, false},
		{"bearer_auth_config", &authn.AuthConfig{RegistryToken: "tok123"}, "Bearer tok123", "", nil, false},
		{"bearer_option_token", nil, "Bearer tok456", "tok456", nil, false},
		{"auth_precedence_docker_over_option", &authn.AuthConfig{Auth: "dXNlcjpwYXNz"}, "Basic dXNlcjpwYXNz", "tok456", nil, false},
		{"identity_token_no_header", &authn.AuthConfig{IdentityToken: "tok999"}, "Bearer tok999", "", nil, true},
		{"anonymous", nil, "", "", nil, false},
		{"credentials_basic", nil, "Basic dXNlcjpwYXNz", "", []types.Credential{{Username: "user", Password: "pass"}}, false},
		{"credentials_over_option_token", nil, "Basic dXNlcjpwYXNz", "tok-ignored", []types.Credential{{Username: "user", Password: "pass"}}, false},
		{"docker_over_credentials", &authn.AuthConfig{RegistryToken: "tok123"}, "Bearer tok123", "", []types.Credential{{Username: "user", Password: "pass"}}, false},
		{"credentials_multiple_last_wins", nil, "Basic dXNlcjI6cGFzczI=", "", []types.Credential{
			{Username: "user1", Password: "pass1"},
			{Username: "user2", Password: "pass2"},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeRegistry(t, tt.wantAuth, false, false)
			defer srv.Close()

			host := strings.TrimPrefix(srv.URL, "http://")
			ref := fmt.Sprintf("%s/repo:tag", host)

			opts := types.ImageOptions{}
			opts.RegistryOptions.Insecure = true
			opts.RegistryOptions.RegistryToken = tt.registryTok
			opts.RegistryOptions.Credentials = tt.credentials

			ctx := context.Background()
			log := logrus.New()

			img, err := NewFromRemote(ctx, log, ref, opts, tt.authCfg)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			_, err = img.Manifest()
			require.NoError(t, err)
		})
	}
}

func TestNewFromRemote_MissingConfigBlob(t *testing.T) {
	srv := fakeRegistry(t, "", true, false)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	ref := fmt.Sprintf("%s/repo:tag", host)

	opts := types.ImageOptions{}
	opts.RegistryOptions.Insecure = true

	ctx := context.Background()
	log := logrus.New()

	img, err := NewFromRemote(ctx, log, ref, opts, nil)
	require.NoError(t, err)

	_, err = img.ConfigFile()
	require.Error(t, err, "missing config blob should cause error")
}
