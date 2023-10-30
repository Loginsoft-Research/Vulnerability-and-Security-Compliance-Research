package GCP_Terraform_gcp_security_gke_enable_private_cluster

deny{
    not(gcp_security_gke_enable_private_cluster)
}

# POLICY 22 [check is same as POLICY 21]
# Clusters should be set to private
# Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.
gcp_security_gke_enable_private_cluster[msg22]{
 input.resource.google_container_cluster[_].network_policy.enabled  == false
 msg22 := "Clusters should be set to private"
 }