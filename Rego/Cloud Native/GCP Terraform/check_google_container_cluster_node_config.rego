package GCP_Terraform_gcp_security_gke_use_service_account

deny{
    not(gcp_security_gke_use_service_account)
}

# POLICY 34
# Checks for service account defined for GKE nodes
# Each GKE node has an Identity and Access Management (IAM) Service Account associated with it. By default, nodes are given the Compute Engine default service account, which you can find by navigating to the IAM section of the Cloud Console. This account has broad access by default, making it useful to wide variety of applications, but it has more permissions than are required to run your Kubernetes Engine cluster. You should create and use a minimally privileged service account for your nodes to use instead of the Compute Engine default service account.
gcp_security_gke_use_service_account{
  check_google_container_cluster_node_config
 } 

check_google_container_cluster_node_config [msg34]{
  check_service_account = input.resource.google_container_cluster[_]
  not check_service_account.node_config.service_account
  msg34 := "Checks for service account defined for GKE nodes - google_container_cluster "
}

check_google_container_cluster_node_config[msg34]{
  check_service_account = input.resource.google_container_node_pool[_]
  not check_service_account.node_config.service_account
  msg34 := "Checks for service account defined for GKE nodes -google_container_node_pool"
}
