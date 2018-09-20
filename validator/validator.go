package validator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/atsushi-ishibashi/cloudtrail-logs-validator/model"
	"github.com/atsushi-ishibashi/cloudtrail-logs-validator/service"
)

type Validator interface {
	Validate(bucket, key string) error
}

type validateClient struct {
	s3svc *service.S3Client
	ctsvc *service.CloudTrailClient
}

func New() Validator {
	return &validateClient{
		s3svc: service.NewS3Client(),
		ctsvc: service.NewCloudTrailClient(),
	}
}

func (c *validateClient) Validate(bucket, key string) error {
	es := make([]error, 0)

	obj, err := c.s3svc.GetFile(bucket, key)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}

	bodyData, err := ioutil.ReadAll(obj.Body)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}

	var digest model.Digest
	if err := json.Unmarshal(bodyData, &digest); err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}
	if digest.DigestS3Bucket != bucket {
		es = append(es, fmt.Errorf("digest.DigestS3Bucket != bucket: %s, %s", digest.DigestS3Bucket, bucket))
		return flattenErrors(es)
	}
	if digest.DigestS3Object != key {
		es = append(es, fmt.Errorf("digest.DigestS3Object != key: %s, %s", digest.DigestS3Object, key))
		return flattenErrors(es)
	}

	signature, ok := obj.Metadata["Signature"]
	if !ok || signature == nil {
		es = append(es, fmt.Errorf("x-amz-meta-signature not found"))
		return flattenErrors(es)
	}

	start, err := time.Parse(time.RFC3339, digest.DigestStartTime)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}
	end, err := time.Parse(time.RFC3339, digest.DigestEndTime)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}
	publicKey, err := c.ctsvc.GetPublicKey(start, end, digest.DigestPublicKeyFingerprint)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}
	rsaPublicKey, err := x509.ParsePKCS1PublicKey(publicKey.Value)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}

	bodyShaHash := sha256.Sum256(bodyData)
	dataToSignString := digest.DigestEndTime + "\n" + digest.DigestS3Bucket + "/" + digest.DigestS3Object + "\n" + hex.EncodeToString(bodyShaHash[:]) + "\n" + digest.PreviousDigestSignature

	d := sha256.Sum256([]byte(dataToSignString))

	signatureContent, _ := hex.DecodeString(*signature)

	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, d[:], signatureContent)
	if err != nil {
		es = append(es, err)
		return flattenErrors(es)
	}

	for _, v := range digest.LogFiles {
		obj, err := c.s3svc.GetFile(v.S3Bucket, v.S3Object)
		if err != nil {
			es = append(es, err)
			continue
		}
		body, _ := ioutil.ReadAll(obj.Body)
		d := sha256.Sum256(body)
		if hex.EncodeToString(d[:]) != v.HashValue {
			es = append(es, fmt.Errorf("logfile verify error: %s", v.S3Object))
		}
	}
	return flattenErrors(es)
}

func flattenErrors(es []error) error {
	if es == nil || len(es) == 0 {
		return nil
	}
	ss := make([]string, len(es))
	for k, v := range es {
		ss[k] = v.Error()
	}
	return errors.New(strings.Join(ss, "\n"))
}
