package GCP_Terraform_gcp_security_compute_no_public_ip

deny{
    not(gcp_security_compute_no_public_ip)
}

# POLICY 14
# Compute instances should not be publicly exposed to the internet
# Google Cloud compute instances that have a public IP address are exposed on the internet and are at risk to attack. 
gcp_security_compute_no_public_ip{
 check_access_config_present_empty
 }
 
check_access_config_present_empty[msg14]{
 access_config :=  input.resource.google_compute_instance[_]
 not access_config.network_interface.access_config
 msg14 := "access_config does not exists."
 }

check_access_config_present_empty[msg14]{
 input.resource.google_compute_instance[_].network_interface.access_config == {}
 msg14 := " Compute instances should not be publicly exposed to the internet, Check if the `access_config` is empty."
}