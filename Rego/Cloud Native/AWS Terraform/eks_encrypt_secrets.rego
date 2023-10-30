package AWS_Terraform_aws_security_eks_encrypt_secrets

deny{
    not (aws_security_eks_encrypt_secrets)
}

#POLICY15 - AWS EKS
# EKS should have the encryption of secrets enabled 
# EKS cluster resources should have the encryption_config block set with protection of the secrets resource.
aws_security_eks_encrypt_secrets[msg15]{
  check_encryption = input.resource.aws_eks_cluster[_]
  not check_encryption.encryption_config
  msg15 := "EKS cluster resources should have the encryption_config block set with protection of the secrets resource."
  }