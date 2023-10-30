package GCP_Terraform_gcp_security_compute_enable_vpc_flow_logs

deny{
    not(gcp_security_compute_enable_vpc_flow_logs)
}

# POLICY 10
# Verify VPC flow logs enabled on compute instances
# VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic. Google Compute Engine subnetworks that do not have VPC flow logs enabled have limited information for auditing and awareness.
# Google Compute Engine subnets configured as INTERNAL_HTTPS_LOAD_BALANCER do not support VPC flow logs. Compute subnetworks with `purpose INTERNAL_HTTPS_LOAD_BALANCER` attribute will not be evaluated.
gcp_security_compute_enable_vpc_flow_logs{
 INTERNAL_HTTPS_LOAD_BALANCER_log_config_check
 }

INTERNAL_HTTPS_LOAD_BALANCER_log_config_check[msg10]{
  input.resource.google_compute_subnetwork[_].purpose == "INTERNAL_HTTPS_LOAD_BALANCER"
  msg10 := "Google Compute Engine subnets configured as INTERNAL_HTTPS_LOAD_BALANCER do not support VPC flow logs"
 }
  
 INTERNAL_HTTPS_LOAD_BALANCER_log_config_check[msg10]{
  config = input.resource.google_compute_subnetwork[_]
  not config.log_config
  msg10 := "VPC flow logs enabled on compute instances must be enabled i.e log config must be present "
 }