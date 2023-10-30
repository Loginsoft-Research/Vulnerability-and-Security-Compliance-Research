package GCP_Terraform_gcp_security_compute_no_default_service_account

deny{
    not(gcp_security_compute_no_default_service_account)
}

# POLICY 11
# Compute instances should not use the default service account
#  The default service account has full project access. Provisioning instances using the default service account gives the instance full access to the project. Compute instances should instead be assigned the minimal access they need.
gcp_security_compute_no_default_service_account[msg11]{
   count(regex.find_n(`.+-compute@developer\.gserviceaccount\.com`, input.resource.google_compute_instance[_].service_account.email, -1)) >0
   msg11 := "Compute instances should not use the default service account"
 }