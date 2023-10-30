package AWS_Terraform_aws_security_s3_bucket_public_read_and_write_prohibited

# deny if Amazon S3 buckets allow public read access
deny{
    not (aws_security_s3_bucket_public_read_and_write_prohibited)
}

# POLICY6 - AWS S3
# acl - (Optional, Deprecated) The canned ACL to apply. Valid values are private, public-read, public-read-write, aws-exec-read, authenticated-read, and log-delivery-write. Defaults to private.
# Ensure Amazon S3 buckets do not allow public read access
aws_security_s3_bucket_public_read_and_write_prohibited[msg5]{
 input.resource.aws_s3_bucket_acl[_].acl == "public-read"
 msg5 := "Amazon S3 buckets must not allow public read access"
}