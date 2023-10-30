package GCP_Terraform_gcp_security_gke_node_pool_uses_cos

deny{
    not(gcp_security_gke_node_pool_uses_cos)
}

# POLICY 30
# Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image
# GKE supports several OS image types but COS_CONTAINERD is the recommended OS image to use on cluster nodes for enhanced security. COS_CONTAINERD is the recommended OS image to use on cluster nodes.
gcp_security_gke_node_pool_uses_cos[msg30]{
   input.resource.google_container_node_pool[_].node_config.image_type != "COS_CONTAINERD"
   msg30 := "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image"
 } 