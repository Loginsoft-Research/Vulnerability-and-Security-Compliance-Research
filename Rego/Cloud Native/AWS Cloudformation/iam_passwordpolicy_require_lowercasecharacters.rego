package aws_cfn_best_practices

default allow = false

allow {
    iamPasswordPolicyRequireLowercaseCharacters
}


iamPasswordPolicyRequireLowercaseCharacters[msg] {
    resource := input.Resources[_]
    resource.Type == "AWS::IAM::AccountPasswordPolicy" 
    resource.Properties.RequireUppercaseCharacters == true
    msg := "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
}
