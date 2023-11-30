package analyzer

import (
	"context"
	"errors"
)

var (
	ErrCacheNotFound = errors.New("blob not found in cache")
)

type CacheClient interface {
	PutBlob(ctx context.Context, key string, blob []byte) error
	GetBlob(ctx context.Context, key string) ([]byte, error)
}
