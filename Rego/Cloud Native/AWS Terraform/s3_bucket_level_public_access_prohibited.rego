package AWS_Terraform_aws_security_s3_bucket_level_public_access_prohibited

# deny if Amazon Simple Storage Service (Amazon S3) buckets are publicly accessible
deny {
    not (aws_security_s3_bucket_level_public_access_prohibited)
}

#POLICY4 - AWS S3
 aws_security_s3_bucket_level_public_access_prohibited[msg3]{
 some i
 input.resource.aws_s3_bucket_public_access_block[i].block_public_acls       == false
 input.resource.aws_s3_bucket_public_access_block[i].block_public_policy     == false
 input.resource.aws_s3_bucket_public_access_block[i].ignore_public_acls      == false
 input.resource.aws_s3_bucket_public_access_block[i].restrict_public_buckets == false
 bucket_name := input.resource.aws_s3_bucket_public_access_block[i].bucket
 msg3:= sprintf("Public access must be prohibited for S3 bucket %v", [bucket_name])
}