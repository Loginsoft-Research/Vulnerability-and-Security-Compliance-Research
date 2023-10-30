package GCP_Terraform_gcp_security_gke_use_cluster_labels

deny{
    not(gcp_security_gke_use_cluster_labels)
}

# POLICY 32
# Clusters should be configured with Labels
# Cluster labels are key-value pairs that helps you organize your Google Cloud clusters. You can attach a label to each resource, then filter the resources based on their labels. Information about labels is forwarded to the billing system, so you can break down your billed charges by label.\n\nThe `resource_labels` argument is optional when using the `google_container_cluster` resource.
gcp_security_gke_use_cluster_labels[msg32]{
   resource_label_check = input.resource.google_container_cluster[_]
   not resource_label_check.resource_labels
   msg32 := "Clusters should be configured with Labels"
 } 