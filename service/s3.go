package service

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

type S3Client struct {
	svc s3iface.S3API
}

func NewS3Client() *S3Client {
	return &S3Client{
		svc: s3.New(session.New(), aws.NewConfig().WithRegion("ap-northeast-1")),
	}
}

func (c *S3Client) GetFile(bucket, key string) (*s3.GetObjectOutput, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	return c.svc.GetObject(input)
}
