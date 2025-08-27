package s3fetcher

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Object struct {
	Key          string
	ETag         string
	LastModified time.Time
}

type S3Fetcher struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3Fetcher buat inisialisasi client
func NewS3Fetcher(bucket, prefix string) (*S3Fetcher, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return &S3Fetcher{
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
		prefix: prefix,
	}, nil
}

// ListObjects ambil semua object metadata di bucket/prefix
func (f *S3Fetcher) ListObjects(ctx context.Context) ([]S3Object, error) {
	var objects []S3Object
	paginator := s3.NewListObjectsV2Paginator(f.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.bucket),
		Prefix: aws.String(f.prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, item := range page.Contents {
			objects = append(objects, S3Object{
				Key:          *item.Key,
				ETag:         *item.ETag,
				LastModified: *item.LastModified,
			})
		}
	}

	return objects, nil
}

// Download file S3 → simpan di temp folder → return local path
func (f *S3Fetcher) Download(ctx context.Context, key string) (string, error) {
	resp, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	tmpDir := os.TempDir()
	localPath := filepath.Join(tmpDir, filepath.Base(key))

	outFile, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", err
	}

	return localPath, nil
}
