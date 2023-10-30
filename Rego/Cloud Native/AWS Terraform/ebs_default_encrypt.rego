package AWS_Terraform_ebs_default_encrypt

# deny if ebs_default_encrypt is not true

deny {
    not (ebs_default_encrypt)  
}

# POLICY 1 - EC2 EBS
#Check if encryption has not been enabled
ebs_default_encrypt[msg]{
  input.resource.aws_ebs_encryption_by_default[_].enabled == false
  input.resource.aws_ebs_volume[_].encrypted              == false
  msg := "AWS EBS encryption must be enabled by default."
  }
