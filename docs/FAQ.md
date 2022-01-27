# Lightspin EKS Creation Engine - Frequently Asked Questions (FAQ)

### 1 - What are the minimal IAM permissions I need to use ECE?

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:UpdateAssumeRolePolicy",
                "ec2:AuthorizeSecurityGroupIngress",
                "eks:ListTagsForResource",
                "iam:ListRoleTags",
                "iam:CreateRole",
                "eks:UpdateClusterConfig",
                "iam:AttachRolePolicy",
                "iam:PutRolePolicy",
                "ssm:GetParameter",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                "eks:DescribeNodegroup",
                "iam:DetachRolePolicy",
                "ec2:RevokeSecurityGroupEgress",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetRole",
                "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
                "iam:GetPolicy",
                "ec2:DescribeLaunchTemplates",
                "iam:ListEntitiesForPolicy",
                "iam:UpdateRoleDescription",
                "ec2:ModifySecurityGroupRules",
                "iam:TagPolicy",
                "ec2:RevokeSecurityGroupIngress",
                "eks:DeleteCluster",
                "eks:CreateFargateProfile",
                "ec2:DescribeSecurityGroupRules",
                "eks:DeleteNodegroup",
                "eks:AccessKubernetesApi",
                "eks:UpdateNodegroupConfig",
                "eks:DescribeCluster",
                "iam:GetRolePolicy",
                "eks:UpdateClusterVersion",
                "iam:UntagRole",
                "kms:PutKeyPolicy",
                "iam:TagRole",
                "iam:DeletePolicy",
                "eks:UpdateNodegroupVersion",
                "eks:AssociateEncryptionConfig",
                "ec2:CreateSecurityGroup",
                "iam:DeleteRolePolicy",
                "kms:ScheduleKeyDeletion",
                "kms:CreateKey",
                "ec2:DeleteLaunchTemplateVersions",
                "iam:ListPolicyTags",
                "eks:CreateCluster",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:DeleteLaunchTemplate",
                "ec2:DescribeLaunchTemplateVersions",
                "iam:ListRoles",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateLaunchTemplateVersion",
                "iam:CreatePolicy",
                "ec2:CreateLaunchTemplate",
                "iam:ListPolicyVersions",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribeVpcs",
                "ec2:DeleteSecurityGroup",
                "iam:UntagPolicy",
                "iam:UpdateRole"
            ],
            "Resource": "*"
        }
    ]
}
```

### 2 - 

### 3 -