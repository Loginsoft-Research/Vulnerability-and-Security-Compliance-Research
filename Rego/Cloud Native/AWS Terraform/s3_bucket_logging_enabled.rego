package AWS_terraform_aws_security_s3_bucket_logging_enabled

# deny if logging is not enabled for your S3 buckets
deny {
    not (aws_security_s3_bucket_logging_enabled)
}

#POLICY5 - AWS S3
#logging attribute is deprecated hence we need to check S3 logging using aws_s3_bucket_logging
#target_bucket - (Required) Name of the bucket where you want Amazon S3 to store server access logs
aws_security_s3_bucket_logging_enabled[msg4]{
 input.resource.aws_s3_bucket_logging[_].target_bucket == null
 msg4 := "Ensure logging is enabled for your S3 buckets"
}