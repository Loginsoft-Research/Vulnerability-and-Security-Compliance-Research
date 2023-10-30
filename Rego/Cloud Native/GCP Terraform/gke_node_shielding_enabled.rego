package GCP_Terraform_gcp_security_gke_node_shielding_enabled

deny{
    not(gcp_security_gke_node_shielding_enabled)
}

# POLICY 31
# Shielded GKE nodes not enabled
# Node identity and integrity can't be verified without shielded GKE nodes. CIS GKE Benchmark Recommendation: 6.5.5. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters
gcp_security_gke_node_shielding_enabled[msg31]{
   input.resource.google_container_cluster[_].enable_shielded_nodes == false
   msg31 := "Shielded GKE nodes not enabled"
 } 