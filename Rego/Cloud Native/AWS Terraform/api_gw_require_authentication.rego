package AWS_terraform_aws_security_api_gw_require_authentication

deny{
    not(aws_security_api_gw_require_authentication)
}

#POLICY11 - AWS API Gateway
# Ensure Authentication for API Gateway methods is activated
aws_security_api_gw_require_authentication[msg11]{
  input.resource.aws_api_gateway_method.any.authorization == "NONE"
  input.resource.aws_api_gateway_method.any.http_method == "OPTION"
  input.resource.aws_api_gateway_method.any.api_key_required == false
  msg11 := "Ensure Authentication for API Gateway methods is activated"
}