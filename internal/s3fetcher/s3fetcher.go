package s3fetcher

import (
	"context"
	"io"
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
	loadOpts := []func(*awsconfig.LoadOptions) error{}

	// Static credentials when supplied; otherwise fall back to the usual AWS
	// chain, which is what an IRSA or instance-role deployment wants.
	if cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(cfg.S3AccessKey, cfg.S3SecretKey, ""),
			),
		)
	}

	region := cfg.S3Region
	if region == "" {
		// MinIO and most S3-compatible servers ignore the region, but the
		// signer requires one.
		region = "us-east-1"
	}
	loadOpts = append(loadOpts, awsconfig.WithRegion(region))

	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(), loadOpts...)
	if err != nil {
		return nil, err
	}

	s3Opts := []func(*s3.Options){}
	if cfg.S3Endpoint != "" {
		// BaseEndpoint rather than the deprecated endpoint resolver, which the
		// SDK now warns about and which silently loses path-style handling.
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3Endpoint)

			// Path style is not optional against a custom endpoint. The default
			// is virtual-hosted style, which puts the bucket in the hostname:
			// against http://127.0.0.1:9000 the SDK tries
			// http://bucket.127.0.0.1:9000 and DNS resolution fails outright.
			// MinIO, Ceph and SeaweedFS all expect the bucket in the path.
			o.UsePathStyle = true
		})
	}

	return &S3Fetcher{
		client: s3.NewFromConfig(awsCfg, s3Opts...),
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

// Open returns the object's body as a stream.
//
// Replaces the old Download, which wrote the object to a temp file and left the
// caller to read it back to hash it. Handing back the stream lets the caller tee
// it through a hasher while writing to disk, so the bytes are read once.
//
// The caller owns the returned ReadCloser and must close it.
func (f *S3Fetcher) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
