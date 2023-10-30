package GCP_Terraform_gcp_security_iam_no_folder_level_service_account_impersonation

deny{
    not(gcp_security_iam_no_folder_level_service_account_impersonation)
}

#POLICY 3
# Users should not be granted service account access at the folder level
# Users with service account access at the folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.
gcp_security_iam_no_folder_level_service_account_impersonation[msg3]{
   count(regex.find_n(`iam\.serviceAccountUser`, input.resource.google_folder_iam_binding[_].role, -1)) >0
   msg3 := "Users should not be granted service account access at the folder level"
 }
