package GCP_Terraform_gcp_security_gke_enable_master_networks

deny{
    not(gcp_security_gke_enable_master_networks)
}

# POLICY 20
# Master authorized networks should be configured on GKE clusters
# Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges.
gcp_security_gke_enable_master_networks[msg20]{
 gke_cluster = input.resource.google_container_cluster[_]
 not gke_cluster.master_authorized_networks_config
 msg20 := "Master authorized networks should be configured on GKE clusters"
 }