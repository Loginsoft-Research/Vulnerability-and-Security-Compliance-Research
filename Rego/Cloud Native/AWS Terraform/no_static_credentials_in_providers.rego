package AWS_Terraform_aws_security_no_static_credentials_in_providers

deny{
    not(aws_security_no_static_credentials_in_providers)
}

#POLICY17 - AWS General
# Providers should not contain hard-coded credentials
aws_security_no_static_credentials_in_providers{
 aws_security_no_static_credentials_in_providers_access_secret_key_check
}


aws_security_no_static_credentials_in_providers_access_secret_key_check[msg17]{
 input.provider.aws.access_key != null
 count(regex.find_n("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", input.provider.aws.access_key, -1)) >0
 input.provider.aws.access_key == "AKIAIOSFODNN7EXAMPLE"
 msg17 := "The aws provider is configured with hard-coded values for access_key"
}

aws_security_no_static_credentials_in_providers_access_secret_key_check[msg17]{
 input.provider.aws.secret_key != null
 count(regex.find_n("([A-Za-z0-9\\\\\\\/+\\\\]{40})", input.provider.aws.secret_key, -1)) >0
 input.provider.aws.secret_key == "wJalrXUtnFEMI/A1AAAAA/bPxRfiCYAAAAAAAKEY"
 msg17 := "The aws provider is configured with hard-coded values for secret key"
}