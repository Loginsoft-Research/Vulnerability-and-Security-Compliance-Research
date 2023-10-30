package AWS_Terraform_aws_security_eks_no_public_cluster_access_to_cidr

deny{
    not (aws_security_eks_no_public_cluster_access_to_cidr)
}

#POLICY16 - AWS EKS
# EKS Clusters should restrict access to public API server
aws_security_eks_no_public_cluster_access_to_cidr[msg16]{
 input.resource.aws_eks_cluster[_].vpc_config.endpoint_public_access == true
 input.resource.aws_eks_cluster[_].vpc_config.public_access_cidrs == "0.0.0.0/0"
 msg16 := "EKS Clusters should restrict access to public API server"
}