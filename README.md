# image-analyzer
OCI images analyzer

This repository exists for 3 reasons:
- `github.com/castai/image-analyzer/image/daemon.Image` interface.
- Having various analyzers bundled in a single module. [This didn't exist at the time of the fork](https://github.com/aquasecurity/trivy/blob/v0.50.1/pkg/fanal/analyzer/all/import.go)
- `https://github.com/aquasecurity/trivy/tree/v0.50.1/pkg/fanal/analyzer/pkg/apk` analyzer not scanning installed binaries.