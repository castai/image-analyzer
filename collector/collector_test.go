package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/castai/image-analyzer"
	mock_blobcache "github.com/castai/image-analyzer/blobscache/mock"
	"github.com/castai/image-analyzer/image/hostfs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestCollector(t *testing.T) {
	t.Run("collect and sends metadata", func(t *testing.T) {
		imgName := "notused"
		imgID := "gke.gcr.io/phpmyadmin@sha256:b0d9c54760b35edd1854e5710c1a62a28ad2d2b070c801da3e30a3e59c19e7e3" //nolint:gosec

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		var receivedMetaBytes []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			data, err := io.ReadAll(req.Body)
			r.NoError(err)
			receivedMetaBytes = data
		}))
		defer srv.Close()

		mockCache := mock_blobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

		c := New(log, image_analyzer.Config{
			ApiURL:    srv.URL,
			ImageID:   imgID,
			ImageName: imgName,
			Timeout:   5 * time.Minute,
			Mode:      image_analyzer.ModeHostFS,
			Runtime:   image_analyzer.RuntimeContainerd,
		}, mockCache, &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: p,
		})

		r.NoError(c.Collect(ctx))

		// Read expect metadata.
		var expected image_analyzer.ImageMetadata
		b, err := os.ReadFile("./testdata/expected_image_scan_meta1.json")
		r.NoError(err)
		r.NoError(json.Unmarshal(b, &expected))

		var receivedMeta image_analyzer.ImageMetadata
		r.NoError(json.Unmarshal(receivedMetaBytes, &receivedMeta))
		r.Equal(expected, receivedMeta)
	})
}

func TestCollectorLargeImageDocker(t *testing.T) {
	// Skip this test by default. Uncomment to run locally.
	if os.Getenv("LOCAL_IMAGE") == "" {
		t.Skip()
	}

	// You will spend a lot of time on macOS to fetch image into temp file from daemon.
	// Instead, export image once to local tar file.
	// docker save ghcr.io/castai/egressd:am1 -o egressd.tar
	imgName := "kvisor:local"
	imgID := imgName

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	//debug.SetGCPercent(-1)
	mockCache := mock_blobcache.MockClient{}

	var receivedMetaBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, err := io.ReadAll(req.Body)
		r.NoError(err)
		receivedMetaBytes = data
	}))
	defer srv.Close()

	c := New(log, image_analyzer.Config{
		ApiURL:            srv.URL,
		ImageID:           imgID,
		ImageName:         imgName,
		Timeout:           5 * time.Minute,
		Mode:              image_analyzer.ModeTarArchive,
		Runtime:           image_analyzer.RuntimeDocker,
		SlowMode:          true,
		ImageLocalTarPath: "egressd.tar",
	}, mockCache, nil)

	go func() {
		for {
			printMemStats()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	r.NoError(c.Collect(ctx))
	writeMemProfile("heap.prof")
	r.NoError(os.WriteFile("metadata.json", receivedMetaBytes, 0600))
}

func printMemStats() {
	runtime.GC() // Get up-to-date statistics.
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("allocs=%d MB, total_allocs=%d MB, sys=%d MB\n", stats.Alloc/1024/1024, stats.TotalAlloc/1024/1024, stats.Sys/1024/1024)
}

func writeMemProfile(name string) {
	f, err := os.Create(name)
	if err != nil {
		logrus.Fatalf("could not create memory profile: %v", err)
	}
	defer f.Close() // error handling omitted for example
	if err := pprof.WriteHeapProfile(f); err != nil {
		logrus.Fatalf("could not write memory profile: %v", err)
	}
}