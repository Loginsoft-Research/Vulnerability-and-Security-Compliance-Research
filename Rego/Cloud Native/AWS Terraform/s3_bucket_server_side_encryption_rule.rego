package AWS_Terraform_aws_security_s3_bucket_server_side_encryption_rule

# deny if  Amazon S3 default encryption is not enabled
deny{
    not(aws_security_s3_bucket_server_side_encryption_rule)
}

# POLICY7 - AWS S3
# Currently, changes to the server_side_encryption_configuration configuration of existing resources cannot be automatically detected by Terraform. To manage changes in encryption of an S3 bucket, use the aws_s3_bucket_server_side_encryption_configuration resource instead. 
# Amazon S3 default encryption is an optional configuration that sets the default encryption behavior for an S3 bucket. Enabling default SSE configures S3 buckets so that all new objects are encrypted when they are stored in the bucket. The objects are encrypted using server-side encryption with either Amazon S3-managed keys (SSE-S3) or AWS KMS keys stored in AWS Key Management Service (AWS KMS) (SSE-KMS).
# Ensure S3 buckets has the Amazon S3 default encryption enabled

aws_security_s3_bucket_server_side_encryption_rule[msg6] {
  check_rule = input.resource.aws_s3_bucket_server_side_encryption_configuration[_]
  not check_rule.rule
  msg6 := "Ensure the rule for S3 buckets is not empty and has the Amazon S3 default encryption enabled"
}

aws_security_s3_bucket_server_side_encryption_rule[msg7] {
  r := input.resource.aws_s3_bucket_server_side_encryption_configuration[_].rule[_]
  not r.apply_server_side_encryption_by_default
  msg7 := "Ensure the rule for S3 bucket has the Amazon S3 default encryption enabled"
}