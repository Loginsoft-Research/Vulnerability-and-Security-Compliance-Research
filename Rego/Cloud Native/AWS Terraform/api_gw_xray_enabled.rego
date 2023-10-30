package AWS_Terraform_aws_security_api_gw_xray_enabled

deny{
    not(aws_security_api_gw_xray_enabled)
}

# POLICY13 - AWS API Gateway
# Ensure AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs
aws_security_api_gw_xray_enabled[msg13]{
  input.resource.aws_api_gateway_stage[_].xray_tracing_enabled == false
  msg13 := "Ensure AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs"
}