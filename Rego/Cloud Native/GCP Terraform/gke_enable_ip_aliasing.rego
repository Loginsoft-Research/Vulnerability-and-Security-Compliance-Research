package GCP_Terraform_gcp_security_gke_enable_ip_aliasing

deny{
    not(gcp_security_gke_enable_ip_aliasing)
}

# POLICY 19
# Clusters should have IP aliasing enabled
# IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.
gcp_security_gke_enable_ip_aliasing[msg19]{
 ip_allocation = input.resource.google_container_cluster[_]
 not ip_allocation.ip_allocation_policy
 msg19 := "Clusters should have IP aliasing enabled"
 }