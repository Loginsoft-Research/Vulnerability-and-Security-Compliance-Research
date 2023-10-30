package AWS_Terraform_

deny{
    (aws_security_iam_no_wildcards_policies)
}

#POLICY14 - AWS IAM
# Resource is either not * or DENY is used (where wildcard is great)
aws_security_iam_no_wildcards_policies {
    resource_wildcard
}

resource_wildcard[msg14] {
    policy := input.resource.aws_iam_policy.policy.policy
    statement := policy.Statement[_]
    statement.Resource == "*"
    msg14 := "AWS IAM policy contains a statement with Resource=*. Please review and update the policy."
}

resource_wildcard[msg15] {
    policy := input.resource.aws_iam_policy.policy.policy
    statement := policy.Statement[_]
    upper(statement.Effect) != "DENY"
     msg15 := "AWS IAM policy contains a statement with Effect != DENY. Please review and update the policy."
}