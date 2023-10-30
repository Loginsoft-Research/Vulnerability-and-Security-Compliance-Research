package GCP_Terraform_gcp_security_gke_enable_auto_repair

deny{
    not(gcp_security_gke_enable_auto_repair)
}

# POLICY 17
# Kubernetes should have 'Automatic repair' enabled
# Automatic repair will monitor nodes and attempt repair when a node fails multiple subsequent health checks. Failing nodes will require manual repair.
gcp_security_gke_enable_auto_repair[msg17]{
 input.resource.google_container_node_pool[_].management.auto_repair == false
 msg17 := "Kubernetes should have 'Automatic repair' enabled"
 }