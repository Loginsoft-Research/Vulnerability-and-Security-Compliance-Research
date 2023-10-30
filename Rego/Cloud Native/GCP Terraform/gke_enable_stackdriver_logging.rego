package GCP_Terraform_gcp_security_gke_enable_stackdriver_logging

deny{
    not(gcp_security_gke_enable_stackdriver_logging)
}

# POLICY 23
# Stackdriver Logging should be enabled
# StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for monitoring, debugging, etc. Without Stackdriver, visibility to the cluster will be reduced.
gcp_security_gke_enable_stackdriver_logging{
  check_logging_service_exists_value
 }

check_logging_service_exists_value[msg23]{
 check_logging_services = input.resource.google_container_cluster[_]
 not check_logging_services.logging_service
 msg23 := "logging_service must be defined"
 }
 
 check_logging_service_exists_value[msg23]{
 input.resource.google_container_cluster[_].logging_service != "logging.googleapis.com/kubernetes"
 msg23 := "Stackdriver Logging should be enabled and set to the proper value logging.googleapis.com/kubernetes"
 }
