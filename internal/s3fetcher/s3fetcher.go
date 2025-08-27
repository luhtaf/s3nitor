package s3fetcher

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Object struct {
	Bucket       string
	Key          string
	ETag         string
	LastModified time.Time
	Size         int64
}

type S3Fetcher struct {
	client *s3.Client
	bucket string
	prefix string
}

func NewS3Fetcher(cfg *config.Config) (*S3Fetcher, error) {
	// default pakai LoadDefaultConfig
	loadOpts := []func(*awsconfig.LoadOptions) error{}

	// kalau ada key/secret di config → pakai static provider
	if cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(cfg.S3AccessKey, cfg.S3SecretKey, ""),
			),
		)
	}

	// kalau ada endpoint MinIO → override resolver
	if cfg.S3Endpoint != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithEndpointResolverWithOptions(
				aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						URL:           cfg.S3Endpoint,
						SigningRegion: "us-east-1", // default, MinIO bebas region
					}, nil
				}),
			),
		)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(), loadOpts...)
	if err != nil {
		return nil, err
	}

	return &S3Fetcher{
		client: s3.NewFromConfig(awsCfg),
		bucket: cfg.S3Bucket,
		prefix: cfg.S3Prefix,
	}, nil
}

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
				Bucket:       f.bucket,
				Key:          aws.ToString(item.Key),
				ETag:         aws.ToString(item.ETag),
				LastModified: aws.ToTime(item.LastModified),
				Size:         *item.Size,
			})
		}
	}
	return objects, nil
}

func (f *S3Fetcher) Download(ctx context.Context, key string) (string, error) {
	resp, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	localPath := filepath.Join(os.TempDir(), filepath.Base(key))
	outFile, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, resp.Body); err != nil {
		return "", err
	}
	return localPath, nil
}
