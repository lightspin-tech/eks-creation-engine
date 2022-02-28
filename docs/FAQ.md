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
                "iam:CreateServiceLinkedRole",
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

### 2 - Can I manage State with ECE?

No, not at this time. There is no inherent state concept nor drift detection in ECE.

### 3 - Can I interact with my EKS Clusters with tools other than ECE?

Yes! You can continue to use `ekstcl`, `boto3`, the AWS CLI and other methods to interact with your EKS Clusters. This may be required for the build out of additional post-hoc infrastructure such as adding Nodegroups or increasing the Nodecount.

### 4 - Can I authorized other IAM Users or Roles? Such as a federate IAM Role or otherwise into the Cluster?

Yes! Use the `--addtl_auth_principals` argument and provide a comma-seperated list of IAM Principal ARNs (Roles & Users) to add to the `system:masters` group within your `kube-config`.

### 5 - Will my `kubectl` context be changed?

Yes. Upon creation of your Cluster, the AWS CLI command `aws eks update-kubeconfig --region $AWS_REGION --name $CLUSTER_NAME` is used to change your `kubectl` context for your newly created Cluster. To switch between different EKS Clusters, created by ECE or otherwise, use the command `kubectl config get-contexts` to see available contexts and finally use `kubectl config use-context $CONTEXT_NAME` to change your context with `kubectl` directly.

### 6 - Will using ECE send any data to Lightspin?

No! ECE is available freely under Apache-2.0 and will not "phone home" or send any data back to us.

## Contact Us :telephone_receiver: :telephone_receiver:

For more information, contact us at support@lightspin.io.

## License :eight_spoked_asterisk: :eight_spoked_asterisk:

This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/eks-creation-engine/blob/main/LICENSE).
