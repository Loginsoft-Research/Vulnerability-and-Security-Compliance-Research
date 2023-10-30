package GCP_Terraform_gcp_security_gke_no_public_control_plane

deny{
    not(gcp_security_gke_no_public_control_plane)
}

# POLICY 28
# GKE Control Plane should not be publicly accessible
# Authorized networks allow you to specify CIDR ranges and allow IP addresses in those ranges to access your cluster control plane endpoint using HTTPS. Exposing the Kubernetes control plane to the public internet by specifying a CIDR block of "0.0.0.0/0" is not recommended. Public clusters can have up to 50 authorized network CIDR ranges; private clusters can have up to 100.
gcp_security_gke_no_public_control_plane[msg28]{
   some i
   input.resource.google_container_cluster[_].master_authorized_networks_config[i].cidr_blocks[j].cidr_block == "0.0.0.0/0"
   msg28 := "GKE Control Plane should not be publicly accessible"
 } 