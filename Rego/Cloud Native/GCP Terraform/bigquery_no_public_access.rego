package GCP_Terraform_gcp_security_bigquery_no_public_access

deny{
    not(gcp_security_bigquery_no_public_access)
}

# POLICY 1
# BigQuery datasets should only be accessible within the organization
# BigQuery datasets should not be configured to provide access to `allAuthenticatedUsers` as this provides any authenticated GCP user, even those outside of your organization, access to your BigQuery dataset. This can lead to exposure of sensitive data to the public internet.
gcp_security_bigquery_no_public_access[msg1]{
  input.resource.google_bigquery_dataset.dataset.access[_].special_group == "allAuthenticatedUsers"
  msg1 := "BigQuery datasets should not be configured to provide access to allAuthenticatedUsers"
 }