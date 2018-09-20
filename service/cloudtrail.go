package service

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
)

var (
	ErrNotFoundExpectedPublicKey = errors.New("not found expected public key")
)

type CloudTrailClient struct {
	svc cloudtrailiface.CloudTrailAPI
}

func NewCloudTrailClient() *CloudTrailClient {
	return &CloudTrailClient{
		svc: cloudtrail.New(session.New(), aws.NewConfig().WithRegion("ap-northeast-1")),
	}
}

func (c *CloudTrailClient) GetPublicKey(start, end time.Time, fingerPrint string) (*cloudtrail.PublicKey, error) {
	input := &cloudtrail.ListPublicKeysInput{
		EndTime:   aws.Time(end),
		StartTime: aws.Time(start),
	}
	resp, err := c.svc.ListPublicKeys(input)
	if err != nil {
		return nil, err
	}
	for _, v := range resp.PublicKeyList {
		if v.Fingerprint != nil && *v.Fingerprint == fingerPrint {
			return v, nil
		}
	}
	return nil, ErrNotFoundExpectedPublicKey
}
