package GCP_Terraform_gcp_security_gke_enable_stackdriver_monitoring

deny{
    not(gcp_security_gke_enable_stackdriver_monitoring)
}

# POLICY 24
# Stackdriver Monitoring should be enabled
# StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.
gcp_security_gke_enable_stackdriver_monitoring{
  check_monitoring_service_exists_value
 }

check_monitoring_service_exists_value[msg24]{
 check_monitoring_services = input.resource.google_container_cluster[_]
 not check_monitoring_services.monitoring_service
 msg24 := "monitoring service must be defined"
 }
 
 check_monitoring_service_exists_value[msg24]{
 input.resource.google_container_cluster[_].monitoring_service != "monitoring.googleapis.com/kubernetes"
 msg24 := "monitoring service should be enabled and set to the proper value monitoring.googleapis.com/kubernetes"
 }