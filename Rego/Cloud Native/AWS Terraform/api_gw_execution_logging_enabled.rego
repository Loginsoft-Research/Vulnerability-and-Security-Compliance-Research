package AWS_Terraform_aws_security_api_gw_execution_logging_enabled

deny{
    not(aws_security_api_gw_execution_logging_enabled)
}

# POLICY10 - AWS API Gateway
# Ensure that all methods in Amazon API Gateway stage have logging enabled
aws_security_api_gw_execution_logging_enabled[msg10] {
    input.resource.aws_api_gateway_stage[_].access_log_settings.destination_arn == null
    msg10 := "Ensure that all methods in Amazon API Gateway stage have logging enabled"
}

# Ensure that all methods in Amazon API Gateway V2 stage have logging enabled
aws_security_api_gw_execution_logging_enabled[msg10] {
    input.resource.aws_apigatewayv2_stage[_].access_log_settings.destination_arn == null
    msg10 := "Ensure that all methods in Amazon API Gateway V2 stage have logging enabled"
}