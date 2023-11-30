module github.com/castai/image-analyzer

go 1.21.4

require (
	github.com/aquasecurity/go-dep-parser v0.0.0-20221114145626-35ef808901e8
	github.com/aquasecurity/trivy v0.35.0
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/containerd/containerd v1.6.8
	github.com/docker/docker v24.0.7+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/google/go-containerregistry v0.12.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/json-iterator/go v1.1.12
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpmdb v0.0.0-20221030142135-919c8a52f04f
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0-rc2
	github.com/samber/lo v1.33.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.1
	golang.org/x/exp v0.0.0-20220823124025-807a23277127
	golang.org/x/sync v0.1.0
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go/compute v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go v66.0.0+incompatible // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.28 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.21 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.11 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.5 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/BurntSushi/toml v1.2.0 // indirect
	github.com/GoogleCloudPlatform/docker-credential-gcr v2.0.5+incompatible // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Microsoft/hcsshim v0.9.4 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/aquasecurity/trivy-db v0.0.0-20220627104749-930461748b63 // indirect
	github.com/aws/aws-sdk-go v1.44.136 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.12.1 // indirect
	github.com/containerd/ttrpc v1.1.1-0.20220420014843-944ef4a40df3 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/cli v20.10.20+incompatible // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/licenseclassifier/v2 v2.0.0-pre6 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/liamg/jfather v0.0.7 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/masahiro331/go-disk v0.0.0-20220919035250-c8da316f91ac // indirect
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20221016160854-4b40d7ee6193 // indirect
	github.com/masahiro331/go-xfs-filesystem v0.0.0-20221127135739-051c25f1becd // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/microsoft/go-rustaudit v0.0.0-20220808201409-204dfee52032 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/buildkit v0.10.4 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20220311020903-6969a0a09ab1 // indirect
	github.com/opencontainers/selinux v1.10.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.23.0 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/oauth2 v0.1.0 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20221018160656-63c7b68cfc55 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.36.0 // indirect
	modernc.org/ccgo/v3 v3.16.6 // indirect
	modernc.org/libc v1.16.7 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.1.1 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/sqlite v1.17.3 // indirect
	modernc.org/strutil v1.1.1 // indirect
	modernc.org/token v1.0.0 // indirect
)
