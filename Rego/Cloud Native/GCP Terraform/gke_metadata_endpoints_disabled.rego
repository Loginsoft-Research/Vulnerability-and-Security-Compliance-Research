package GCP_Terraform_gcp_security_gke_metadata_endpoints_disabled

deny{
    not(gcp_security_gke_metadata_endpoints_disabled)
}

# POLICY 25
# Legacy metadata endpoints enabled
# The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. Unless specifically required, we recommend you disable these legacy APIs. When setting the `metadata` block, the default value for `disable-legacy-endpoints` is set to `true`, they should not be explicitly enabled.
gcp_security_gke_metadata_endpoints_disabled[msg25]{
   check_metadata = input.resource.google_container_cluster[_]
   check_metadata.metadata[`disable-legacy-endpoints`] == false
   msg25 := "Legacy metadata endpoints must be enabled"
 }
