package GCP_Terraform_gcp_security_iam_no_privileged_service_accounts

deny{
    not(gcp_security_iam_no_privileged_service_accounts)
}

# POLICY 4
# Service accounts should not have roles assigned with excessive privileges
# Service accounts should have a minimal set of permissions assigned to accomplish their job. They should never have excessive access because if compromised, an attacker can escalate privileges and take over the entire account.
gcp_security_iam_no_privileged_service_accounts{
  role_owner_editor 
 }

 role_owner_editor[msg4]{
 count(regex.find_n(`roles\/owner`, input.resource.google_project_iam_member[_].role, -1)) >0
 msg4 := "Service accounts should not have roles assigned with excessive privileges - Role Owner"
 }

  role_owner_editor[msg4]{
 count(regex.find_n(`roles\/editor`, input.resource.google_project_iam_member[_].role, -1)) >0
 msg4 := "Service accounts should not have roles assigned with excessive privileges - Role Editor"
 }