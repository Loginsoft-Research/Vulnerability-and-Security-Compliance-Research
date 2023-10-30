package AWS_Terraform_aws_security_ec2_imdsv2

# deny if Instance Metadata Service Version 2 (IMDSv2) with session authentication tokens is not active
deny {
    not (aws_security_ec2_imdsv2)
}

#POLICY3 - EC2
#Ensure Instance Metadata Service Version 2 (IMDSv2) with session authentication tokens is active
aws_security_ec2_imdsv2[msg2]{
  #valid value of http_tokens must be required and valid value of http_endpoint must be disabled

  #http_tokens is to ensure that EC2 instance's metadata service is accessible via the instance's default network interface.
  #session authentication tokens (IMDSv2), which can be enforced using the http_tokens attribute with the value "required".
  input.resource.aws_instance[_].metadata_options.http_tokens   == "optional"
  
  #http_endpoint controls whether the service is accessible via the default network interface. 
  #When http_endpoint is set to "disabled", the URL is no longer accessible, and metadata can only be accessed via other means, such as the AWS CLI or SDKs.
  input.resource.aws_instance[_].metadata_options.http_endpoint == "enabled"
  msg2 := "Ensure Instance Metadata Service Version 2 (IMDSv2) with session authentication tokens is active"
}
