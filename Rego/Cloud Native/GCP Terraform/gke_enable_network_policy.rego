package GCP_Terraform_gcp_security_gke_enable_network_policy

deny{
    not(gcp_security_gke_enable_network_policy)
}

# POLICY 21
# Network Policy should be enabled on GKE clusters
# Enabling a network policy allows the segregation of network traffic by namespace.
gcp_security_gke_enable_network_policy[msg21]{
 input.resource.google_container_cluster[_].network_policy.enabled  == false
 msg21 := "Network Policy should be enabled on GKE clusters"
 }