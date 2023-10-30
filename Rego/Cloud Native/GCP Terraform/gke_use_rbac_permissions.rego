package GCP_Terraform_gcp_security_gke_use_rbac_permissions

deny{
    not(gcp_security_gke_use_rbac_permissions)
}

# POLICY 33
# Legacy ABAC permissions are enabled
# Cluster labels are key-value pairs that helps you organize your Google Cloud clusters. You can attach a label to each resource, then filter the resources based on their labels. Information about labels is forwarded to the billing system, so you can break down your billed charges by label.\n\nThe `resource_labels` argument is optional when using the `google_container_cluster` resource.
gcp_security_gke_use_rbac_permissions[msg33]{
   input.resource.google_container_cluster[_].enable_legacy_abac == true
   msg33 := "Legacy ABAC permissions are enabled"
 } 