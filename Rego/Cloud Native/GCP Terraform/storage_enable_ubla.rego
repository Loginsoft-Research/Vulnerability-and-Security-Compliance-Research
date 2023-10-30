package GCP_Terraform_gcp_security_storage_enable_ubla

deny{
    not(gcp_security_storage_enable_ubla)
}

# POLICY 5
# Ensure that Cloud Storage buckets have uniform bucket-level access enabled
# Google Cloud Storage buckets should be configured with uniform bucket-level access.
gcp_security_storage_enable_ubla[msg5]{
  input.resource.google_storage_bucket[_].uniform_bucket_level_access == false
  msg5 := "Ensure that Cloud Storage buckets have uniform bucket-level access enabled"
 }