package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/atsushi-ishibashi/cloudtrail-logs-validator/service"
	"github.com/atsushi-ishibashi/cloudtrail-logs-validator/validator"
)

var (
	s3svc *service.S3Client
	ctsvc *service.CloudTrailClient
)

var (
	bucket = flag.String("bucket", "", "bucket")
	key    = flag.String("key", "", "digest key")
)

func init() {
	s3svc = service.NewS3Client()
	ctsvc = service.NewCloudTrailClient()
}

func main() {
	flag.Parse()

	if *bucket == "" {
		log.Fatalln("bucket required")
	}
	if *key == "" {
		log.Fatalln("key required")
	}

	validator := validator.New()

	err := validator.Validate(*bucket, *key)
	if err != nil {
		fmt.Println(err)
	}
}
