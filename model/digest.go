package model

type Digest struct {
	AWSAccountID                string     `json:"awsAccountId"`
	DigestStartTime             string     `json:"digestStartTime"`
	DigestEndTime               string     `json:"digestEndTime"`
	DigestS3Bucket              string     `json:"digestS3Bucket"`
	DigestS3Object              string     `json:"digestS3Object"`
	DigestPublicKeyFingerprint  string     `json:"digestPublicKeyFingerprint"`
	DigestSignatureAlgorithm    string     `json:"digestSignatureAlgorithm"`
	NewestEventTime             string     `json:"newestEventTime"`
	OldestEventTime             string     `json:"oldestEventTime"`
	PreviousDigestS3Bucket      string     `json:"previousDigestS3Bucket"`
	PreviousDigestS3Object      string     `json:"previousDigestS3Object"`
	PreviousDigestHashValue     string     `json:"previousDigestHashValue"`
	PreviousDigestHashAlgorithm string     `json:"previousDigestHashAlgorithm"`
	PreviousDigestSignature     string     `json:"previousDigestSignature"`
	LogFiles                    []*LogFile `json:"logFiles"`
}

type LogFile struct {
	S3Bucket        string `json:"s3Bucket"`
	S3Object        string `json:"s3Object"`
	HashValue       string `json:"hashValue"`
	HashAlgorithm   string `json:"hashAlgorithm"`
	NewestEventTime string `json:"newestEventTime"`
	OldestEventTime string `json:"oldestEventTime"`
}
