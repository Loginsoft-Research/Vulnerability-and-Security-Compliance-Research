package GCP_Terraform_gcp_security_storage_no_public_access

deny{
    not(gcp_security_storage_no_public_access)
}

# POLICY 6
# Ensure that Cloud Storage bucket is not publicly accessible
# Google Cloud Storage buckets that define 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organization. This can lead to exposure of sensitive data. The recommended approach is to restrict public access.
gcp_security_storage_no_public_access{
 public_access 
 }
 
 public_access[msg6]{
  input.resource.google_storage_bucket_iam_binding[_].members[_] == "allAuthenticatedUsers" 
  msg6 := "allAuthenticatedUsers - Ensure that Cloud Storage bucket is not publicly accessible"
 }
 
 public_access[msg6]{
  input.resource.google_storage_bucket_iam_binding[_].members[_] == "allUsers"
  msg6 := "allUsers -Ensure that Cloud Storage bucket is not publicly accessible"
 }
