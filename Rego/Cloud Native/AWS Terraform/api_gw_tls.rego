package AWS_terraform_aws_security_api_gw_tls

deny{
    not(aws_security_api_gw_tls)
}

# POLICY12 - AWS API Gateway
# Ensure that the API Gateway uses a secure SSL/TLS configuration - security_policy should be set to TLS-1-2
aws_security_api_gw_tls[msg12]{
  input.resource.aws_api_gateway_domain_name[_].security_policy == "TLS_1_0"
  msg12 := " Ensure that the API Gateway uses a secure SSL/TLS configuration"
}