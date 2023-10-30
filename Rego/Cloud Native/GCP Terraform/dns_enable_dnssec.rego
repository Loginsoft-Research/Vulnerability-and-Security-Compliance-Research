package GCP_Terraform_gcp_security_dns_enable_dnssec

deny{
    not(gcp_security_dns_enable_dnssec)
}

# POLICY 15
# Cloud DNS should use DNSSEC
# DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation. Unverified DNS responses could lead to man-in-the-middle attacks. 
gcp_security_dns_enable_dnssec[msg15]{
 input.resource.google_dns_managed_zone[_].dnssec_config.state == "off"
 msg15 := " Cloud DNS should use DNSSEC which will prevent MITM attacks"
 }