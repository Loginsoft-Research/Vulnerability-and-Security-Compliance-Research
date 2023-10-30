package GCP_Terraform_gcp_security_iam_no_folder_level_default_service_account_assignment

deny{
    not(gcp_security_iam_no_folder_level_default_service_account_assignment)
}

#POLICY 2
# Roles should not be assigned to default service accounts
# Default service accounts should not be used when granting access to folders as this can violate least privilege. It is recommended to use specialized service accounts instead.
gcp_security_iam_no_folder_level_default_service_account_assignment[msg2]{
   count(regex.find_n(`.+@appspot\.gserviceaccount\.com$`, input.resource.google_folder_iam_member[_].member, -1)) >0
   count(regex.find_n(`.+-compute@developer\.gserviceaccount\.com$`, input.resource.google_folder_iam_member[_].member, -1)) >0
   count(regex.find_n(`data\.google_compute_default_service_account`, input.resource.google_folder_iam_member[_].member, -1)) >0
   msg2 := "Roles should not be assigned to default service accounts"
 }