package GCP_Terraform_gcp_security_gke_node_metadata_security

deny{
    not(gcp_security_gke_node_metadata_security)
}

# POLICY 29
# Node metadata value disables metadata concealment
# GKE metadata concealment protects some potentially sensitive system metadata from user workloads running on your cluster. Metadata concealment is scheduled to be deprecated in the future and Google recommends using Workload Identity instead of metadata concealment. This check is looking for configuration that exposes metadata completely.
gcp_security_gke_node_metadata_security[msg29]{
   input.resource.google_container_node_pool[_].node_config.workload_metadata_config.node_metadata == "EXPOSE"
   msg29 := "Node metadata value disables metadata concealment"
 } els[msg29] = true {
   input.resource.google_container_node_pool[_].node_config.workload_metadata_config.node_metadata == "UNSPECIFIED"
   msg29 := "Node metadata value disables metadata concealment"
 }