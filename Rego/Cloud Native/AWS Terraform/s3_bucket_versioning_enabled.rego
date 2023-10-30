package AWS_Terraform_aws_security_s3_bucket_versioning_enabled

# deny if versioning is not enabled for your S3 buckets
deny{
       not (aws_security_s3_bucket_versioning_enabled)
}

#POLICY8 - AWS S3
# Ensure that versioning is enabled for your S3 buckets
# Valid values of versioning_configuration status are: Enabled, Suspended, or Disabled
aws_security_s3_bucket_versioning_enabled[msg8]{
 input.resource.aws_s3_bucket_versioning[_].versioning_configuration.status == "Disabled"
 msg8 := "Ensure that versioning is enabled for your S3 buckets"
}