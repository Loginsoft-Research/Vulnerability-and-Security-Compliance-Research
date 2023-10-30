package GCP_Terraform_gcp_security_dns_key_check

deny{
    not(gcp_security_dns_key_check)
}

# POLICY 16
# Zone signing should not use RSA SHA1 -Datasource
# RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512.
gcp_security_dns_key_check[msg16]{
 input.data.google_dns_keys[_].key_signing_keys.algorithm == "rsasha1"
 msg16 := "Zone signing should not use RSA SHA1"
 }