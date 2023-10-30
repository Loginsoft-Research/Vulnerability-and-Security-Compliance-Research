package GCP_Terraform_gcp_security_gke_no_basic_authentication

deny{
    not(gcp_security_gke_no_basic_authentication)
}

# POLICY 26
# Clusters should not use basic authentication
#There are several methods of authenticating to the Kubernetes API server. In GKE, the supported methods are service account bearer tokens, OAuth tokens, and x509 client certificates. Prior to GKE's integration with OAuth, a one-time generated x509 certificate or static password were the only available authentication methods, but are now not recommended and should be disabled. These methods present a wider surface of attack for cluster compromise and have been disabled by default since GKE version 1.12. If you are using legacy authentication methods, we recommend that you turn them off. Authentication with a static password is deprecated and has been removed since GKE version 1.19.
gcp_security_gke_no_basic_authentication[msg26]{
   input.resource.google_container_cluster[_].master_auth.username == ""
   msg26 := "Legacy metadata endpoints must be enabled -Username must not be empty"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.username == null
   msg26 := "Legacy metadata endpoints must be enabled -Username must not be null"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.password == ""
   msg26 := "Legacy metadata endpoints must be enabled - Password must not be empty"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.password == null
   msg26 := "Legacy metadata endpoints must be enabled - Password must not be null"
 }