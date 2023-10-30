package AWS_Terraform_aws_security_api_gw_cache_enabled_and_encrypted

# deny if all methods in Amazon API Gateway stages have no cache enabled and no cache encrypted
deny{
    not(aws_security_api_gw_cache_enabled_and_encrypted)
}

#POLICY9 - AWS API Gateway
#Ensure that all methods in Amazon API Gateway stages have cache enabled and cache encrypted
aws_security_api_gw_cache_enabled_and_encrypted[msg9]{
 input.resource.aws_api_gateway_method_settings[_].settings.cache_data_encrypted == false
 msg9 := "Ensure that all methods in Amazon API Gateway stages have cache enabled and cache encrypted"
}