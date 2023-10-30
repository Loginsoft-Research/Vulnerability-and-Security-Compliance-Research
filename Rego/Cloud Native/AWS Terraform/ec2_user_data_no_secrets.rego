package AWS_Terraform_ec2_user_data_no_secrets

deny {
    not (ec2_user_data_no_secrets)
}

#POLICY2 - EC2
#Ensure EC2 instance user data does not contain secrets
ec2_user_data_no_secrets[msg1]{
  check_sample_access_secret_key
  msg1 := "Ensure AWS EC2 instance user data should not contain any secrets"
}

check_sample_access_secret_key{
  # ensure that all used AWS_ACCESS_KEY_ID are the sample key (access_key) - AKIAIOSFODNN7EXAMPLE
  count(regex.find_n(".*(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}.*", input.resource.aws_instance[_].user_data, -1)) >0
}

check_sample_access_secret_key{
  # ensure that all used secret keys are the sample key (secret_key) - wJalrXUtnFEMI/A1AAAAA/bPxRfiCYAAAAAAAKEY
  count(regex.find_n("([A-Za-z0-9\\\\\\\/+\\\\]{40})", input.resource.aws_instance[_].user_data,-1))>0
}