package GCP_Terraform_gcp_security_gke_enable_auto_upgrade

deny{
    not(gcp_security_gke_enable_auto_upgrade)
}

# POLICY 18
#Kubernetes should have 'Automatic upgrade' enabled
# Automatic updates keep nodes updated with the latest cluster master version.
gcp_security_gke_enable_auto_upgrade[msg18]{
 input.resource.google_container_node_pool[_].management.auto_upgrade  == false
 msg18 := "Kubernetes should have 'Automatic upgrade' enabled"
 }