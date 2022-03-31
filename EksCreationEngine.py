#This file is part of Lightspin EKS Creation Engine.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#'License'); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

import base64
import sys
import boto3
import botocore.exceptions
import json
from datetime import datetime
import time
import subprocess
import re
from plugins.ECEDatadog import DatadogSetup
from plugins.ECEFalco import FalcoSetup
from plugins.ECENonameSecurity import NonameSecuritySetup

cache = list()

class ClusterManager():

    def get_latest_eks_optimized_ubuntu(kubernetes_version, ami_id, ami_os, ami_architecture):
        '''
        This function either receives an AMI ID from main.py or receives the default value of 'SSM' which is matched against the arguments
        `ami_os` and `ami_architecture` to dynamically pull the latest, stable AMI from SSM Public Parameters.
        '''
        ssm = boto3.client('ssm')

        if ami_id == 'SSM':
            # Ubuntu 20.04 LTS
            if ami_os == 'ubuntu':
                # AMD64
                if ami_architecture == 'amd64':
                    # /aws/service/canonical/ubuntu/eks/20.04/1.21/stable/current/amd64/hvm/ebs-gp2/ami-id
                    publicParameter = str(f'/aws/service/canonical/{ami_os}/eks/20.04/{kubernetes_version}/stable/current/{ami_architecture}/hvm/ebs-gp2/ami-id')
                # ARM64
                else:
                    # /aws/service/canonical/ubuntu/eks/20.04/1.21/stable/current/arm64/hvm/ebs-gp2/ami-id
                    publicParameter = str(f'/aws/service/canonical/{ami_os}/eks/20.04/{kubernetes_version}/stable/current/{ami_architecture}/hvm/ebs-gp2/ami-id')
            # Amazon Linux 2
            # Public Params search in the console is fucky, check here: https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html
            else:
                # AMD64
                if ami_architecture == 'amd64':
                    # /aws/service/eks/optimized-ami/1.21/amazon-linux-2/recommended/image_id
                    publicParameter = str(f'/aws/service/eks/optimized-ami/{kubernetes_version}/amazon-linux-2/recommended/image_id')
                # ARM64
                else:
                    # /aws/service/eks/optimized-ami/1.21/amazon-linux-2-arm64/recommended/image_id
                    publicParameter = str(f'/aws/service/eks/optimized-ami/{kubernetes_version}/amazon-linux-2-arm64/recommended/image_id')

            # retrieve the AMI ID and return it
            try:
                amiId = ssm.get_parameter(Name=publicParameter)['Parameter']['Value']
            except Exception as e:
                raise e
        else:
            amiId = ami_id
            del ami_os
            del ami_architecture

        del ssm
        del publicParameter

        print(f'Your EKS Nodegroup AMI is {amiId}')

        return amiId

    def create_cluster_svc_role(cluster_role_name):
        '''
        This function creates a Cluster Service Role for EKS, required for Cluster Creation
        '''
        iam = boto3.client('iam')
        sts = boto3.client('sts')
        acctId = sts.get_caller_identity()['Account']
        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        # Trust Policy for EKS
        trustPolicy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'eks.amazonaws.com'
                    },
                    'Action': 'sts:AssumeRole'
                }
            ]
        }

        try:
            r = iam.create_role(
                Path='/',
                RoleName=cluster_role_name,
                AssumeRolePolicyDocument=json.dumps(trustPolicy),
                Description='Allows access to other AWS service resources that are required to operate clusters managed by EKS',
                MaxSessionDuration=3600,
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': cluster_role_name
                    },
                    {
                        'Key': 'CreatedBy',
                        'Value': createdBy
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': createdAt
                    },
                    {
                        'Key': 'CreatedWith',
                        'Value': 'Lightspin ECE'
                    }
                ]
            )
            # Attach required Cluster Policy (AWS Managed) or get following error
            # botocore.errorfactory.InvalidParameterException: An error occurred (InvalidParameterException) when calling the CreateCluster operation: The provided role doesn't have the Amazon EKS Managed Policies associated with it. Please ensure the following policies [arn:aws:iam::aws:policy/AmazonEKSClusterPolicy] are attached
            waiter = iam.get_waiter('role_exists')

            waiter.wait(
                RoleName=cluster_role_name,
                WaiterConfig={
                    'Delay': 3,
                    'MaxAttempts': 20
                }
            )

            iam.attach_role_policy(
                RoleName=cluster_role_name,
                PolicyArn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            )
            roleArn = str(r['Role']['Arn'])
        except botocore.exceptions.ClientError as error:
            # If we have an 'EntityAlreadyExists' error it means a Role of the same name exists, we can try to use it instead
            if error.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f'The supplied role name of {cluster_role_name} already exists, attempting to use it')
                roleArn = f'arn:aws:iam::{acctId}:role/{cluster_role_name}'
            else:
                print(f'Error encountered: {error}')
                RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.WaiterError as we:
            print(f'Error encountered: {we}')
            RollbackManager.rollback_from_cache(cache=cache)

        del iam
        del sts
        del acctId
        del trustPolicy

        print(f'Your cluster role ARN is {roleArn}')
        return roleArn

    def create_managed_nodegroup_s3_policy(bucket_name, nodegroup_role_name):
        '''
        Creates an IAM Policy that allows S3 GetObject permissions for use in the Nodegroup Role
        '''
        iam = boto3.client('iam')
        sts = boto3.client('sts')
        acctId = sts.get_caller_identity()['Account']
        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())
        policyName = f'{nodegroup_role_name}Policy'

        iamPolicyDoc = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'GetObjectSid',
                    'Effect': 'Allow',
                    'Action': [
                        's3:GetObjectAcl',
                        's3:GetObject',
                        's3:GetBucketAcl',
                        's3:GetBucketLocation'
                    ],
                    'Resource': [
                        f'arn:aws:s3:::{bucket_name}/*',
                        f'arn:aws:s3:::{bucket_name}'
                    ]
                }
            ]
        }

        try:
            r = iam.create_policy(
                PolicyName=policyName,
                Path='/',
                PolicyDocument=json.dumps(iamPolicyDoc),
                Description='Allows access to specific S3 buckets for node groups managed by EKS - Created by Lightspin ECE',
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': policyName
                    },
                    {
                        'Key': 'CreatedBy',
                        'Value': createdBy
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': createdAt
                    },
                    {
                        'Key': 'CreatedWith',
                        'Value': 'Lightspin ECE'
                    }
                ]
            )
            policyArn = str(r['Policy']['Arn'])
        except botocore.exceptions.ClientError as error:
            # If we have an 'EntityAlreadyExists' error it means a Role of the same name exists, we can try to use it instead
            # we will assume it has the right permissions after all
            if error.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f'The supplied role policy name of {policyName} already exists, attempting to use it')
                policyArn = f'arn:aws:iam::{acctId}:policy/{policyName}'
            else:
                print(f'Error encountered: {error}')
                RollbackManager.rollback_from_cache(cache=cache)

        del iam
        del sts
        del acctId
        del iamPolicyDoc
        del policyName

        print(f'Your node group role policy ARN is {policyArn}')
        return policyArn

    def create_managed_nodegroup_role(bucket_name, nodegroup_role_name, mde_on_nodes):
        '''
        This function creates a Nodegroup Service Role for EKS, which gives Nodes permissions to interact with AWS APIs.
        This function calls the `create_managed_nodegroup_s3_policy` function and passes the S3 Bucket name specified in
        main.py to allow your Nodegroup Role to communicate with the S3 bucket for bootstrapping purposes
        '''
        iam = boto3.client('iam')
        sts = boto3.client('sts')
        acctId = sts.get_caller_identity()['Account']
        roleName = nodegroup_role_name
        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        # Static list of required AWS Managed Policies for EKS Managed Nodegroup Roles
        # Adding SSM for SSM access as SSH Keypairs are not specified
        nodegroupAwsManagedPolicies = [
            'arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
            'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly',
            'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
            'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
        ]

        # Grab S3 Node Group policy from other Function & add to List if MDE is enabled
        if mde_on_nodes == 'True':
            s3PolicyArn = ClusterManager.create_managed_nodegroup_s3_policy(bucket_name, nodegroup_role_name)
            nodegroupAwsManagedPolicies.append(s3PolicyArn)

        # Trust Policy for EKS NodeGroup Role trusts EC2
        trustPolicy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'ec2.amazonaws.com'
                    },
                    'Action': 'sts:AssumeRole'
                }
            ]
        }

        try:
            r = iam.create_role(
                Path='/',
                RoleName=roleName,
                AssumeRolePolicyDocument=json.dumps(trustPolicy),
                Description='Allows access to other AWS service resources that are required to operate node groups managed by EKS',
                MaxSessionDuration=3600,
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': roleName
                    },
                    {
                        'Key': 'CreatedBy',
                        'Value': createdBy
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': createdAt
                    },
                    {
                        'Key': 'CreatedWith',
                        'Value': 'Lightspin ECE'
                    }
                ]
            )
            roleArn = str(r['Role']['Arn'])

            waiter = iam.get_waiter('role_exists')
            waiter.wait(
                RoleName=roleName,
                WaiterConfig={
                    'Delay': 3,
                    'MaxAttempts': 20
                }
            )

        except botocore.exceptions.ClientError as error:
            # If we have an 'EntityAlreadyExists' error it means a Role of the same name exists, we can try to use it instead
            # we will assume it has the right permissions after all
            if error.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f'The supplied role name of {roleName} already exists, attempting to use it')
                roleArn = f'arn:aws:iam::{acctId}:role/{roleName}'
            else:
                print(f'Error encountered: {error}')
                RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.WaiterError as we:
            print(f'Error encountered: {we}')
            RollbackManager.rollback_from_cache(cache=cache)

        # Loop through List of policies and attach Policies to Role, handle errors if already attached
        try:
            for policy in nodegroupAwsManagedPolicies:
                iam.attach_role_policy(
                    RoleName=roleName,
                    PolicyArn=policy
                )
        except Exception as e:
            print(f'Error encountered: {e}')
            RollbackManager.rollback_from_cache(cache=cache)

        del iam
        del sts
        del acctId
        del trustPolicy
        del roleName

        print(f'Your node group role ARN is {roleArn}')
        return roleArn

    def cluster_security_group_factory(cluster_name, vpc_id, additional_ports):
        '''
        This function creates a minimum necessary Security Group for your EKS Cluster based on AWS reccomendations
        https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html this will also add permissions to ports
        TCP 2801 and TCP 8765 for FalcoSidekick and Falco Security, respectively, for At-Create or later configuration
        of Falco in a Cluster which provides real-time protection and event forwarding
        '''

        ec2 = boto3.client('ec2')
        sts = boto3.client('sts')

        print(f'Setting up a Security Group for VPC {vpc_id} for EKS Cluster {cluster_name}')

        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        # Generate SG Name, passed to the create_security_group() method, and used for general messaging
        sgName = str(f'{cluster_name}ClusterSG')

        # Load constants of ports needed reccomended by AWS and needed by Falco/Falco Sidekick
        defaultPortSet = [53, 443, 2801, 8765, 10250]
        # if extra ports have been provided via main.py, merge the lists and check for duplicates
        if additional_ports:
            for p in additional_ports:
                if int(p) not in defaultPortSet:
                    defaultPortSet.append(int(p))
        
        # remove the list, it's not needed anymore
        del additional_ports

        # Create an empty list to store all IPv4 CIDRs as VPCs may have additional IPV4 CIDRs associated
        allVpcCidrs = []

        # Get CIDR information on the VPC
        try:
            r = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
            vpcMainCidr = str(r['CidrBlock'])
            allVpcCidrs.append(vpcMainCidr)

            # Loop additional CIDRs if they exist and are associated
            for cidr in r['CidrBlockAssociationSet']:
                if str(cidr['CidrBlockState']['State']) == 'associated':
                    if str(cidr['CidrBlock']) not in allVpcCidrs:
                        allVpcCidrs.append(str(cidr['CidrBlock']))
        except KeyError as ke:
            print(f'Error encountered: {ke}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)

        # All CIDRs collected and ports consolidated, Security Group creation starts now
        try:
            r = ec2.create_security_group(
                Description=f'Security Group for EKS Cluster {cluster_name} - Created by {createdBy} using Lightspin ECE',
                GroupName=sgName,
                VpcId=vpc_id,
                TagSpecifications=[
                    {
                        'ResourceType': 'security-group',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': sgName
                            },
                            {
                                'Key': 'CreatedBy',
                                'Value': createdBy
                            },
                            {
                                'Key': 'CreatedAt',
                                'Value': createdAt
                            },
                            {
                                'Key': 'CreatedWith',
                                'Value': 'Lightspin ECE'
                            },
                            # This tag is required per AWS Docs
                            # One, and only one, of the security groups associated to your nodes should have the following tag applied: For more information about tagging, see Working with tags using the console. kubernetes.io/cluster/cluster-name: owned
                            {
                                'Key': f'kubernetes.io/cluster/{cluster_name}',
                                'Value': 'owned'
                            }
                        ]
                    }
                ]
            )
            secGroupId = str(r['GroupId'])

            sgCache = {
                'ClusterSecurityGroupId': secGroupId
            }
            cache.append(sgCache)

            print(f'Added {sgName} ID {secGroupId} to Cache')
            print(f'Authorizing ingress for Ports {defaultPortSet} for CIDRS {allVpcCidrs} for {sgName}')

            # Now start adding Inbound Rules per CIDR and per Port
            # Add conditional logic for port 53 (DNS) to create both TCP and UDP Rules
            for cidr in allVpcCidrs:
                for port in defaultPortSet:
                    if port == 53:
                        ec2.authorize_security_group_ingress(
                            GroupId=secGroupId,
                            IpPermissions=[
                                {
                                    'FromPort': int(port),
                                    'ToPort': int(port),
                                    'IpProtocol': 'tcp',
                                    'IpRanges': [
                                        {
                                            'CidrIp': cidr,
                                            'Description': f'Allow tcp {port} to {cidr}'
                                        }
                                    ]
                                },
                                {
                                    'FromPort': int(port),
                                    'ToPort': int(port),
                                    'IpProtocol': 'udp',
                                    'IpRanges': [
                                        {
                                            'CidrIp': cidr,
                                            'Description': f'Allow udp {port} to {cidr}'
                                        }
                                    ]
                                }
                            ],
                            TagSpecifications=[
                                {
                                    'ResourceType': 'security-group-rule',
                                    'Tags': [
                                        {
                                            'Key': 'Name',
                                            'Value': f'{sgName}{cidr}{port}'
                                        },
                                        {
                                            'Key': 'CreatedBy',
                                            'Value': createdBy
                                        },
                                        {
                                            'Key': 'CreatedAt',
                                            'Value': createdAt
                                        },
                                        {
                                            'Key': 'CreatedWith',
                                            'Value': 'Lightspin ECE'
                                        }
                                    ]
                                }
                            ]
                        )
                    else:
                        ec2.authorize_security_group_ingress(
                            GroupId=secGroupId,
                            IpPermissions=[
                                {
                                    'FromPort': int(port),
                                    'ToPort': int(port),
                                    'IpProtocol': 'tcp',
                                    'IpRanges': [
                                        {
                                            'CidrIp': cidr,
                                            'Description': f'Allow tcp {port} to {cidr}'
                                        }
                                    ]
                                }
                            ],
                            TagSpecifications=[
                                {
                                    'ResourceType': 'security-group-rule',
                                    'Tags': [
                                        {
                                            'Key': 'Name',
                                            'Value': f'{sgName}{cidr}{port}'
                                        },
                                        {
                                            'Key': 'CreatedBy',
                                            'Value': createdBy
                                        },
                                        {
                                            'Key': 'CreatedAt',
                                            'Value': createdAt
                                        },
                                        {
                                            'Key': 'CreatedWith',
                                            'Value': 'Lightspin ECE'
                                        }
                                    ]
                                }
                            ]
                        )

            # Adding inbound rules per Port for the Security Group itself (talk to self for Node-Cluster Comms)
            for port in defaultPortSet:
                if port == 53:
                    ec2.authorize_security_group_ingress(
                        GroupId=secGroupId,
                        IpPermissions=[
                            {
                                'FromPort': int(port),
                                'ToPort': int(port),
                                'IpProtocol': 'tcp',
                                'UserIdGroupPairs': [
                                    {
                                        'Description': f'Allow tcp {port} to {secGroupId}',
                                        'GroupId': secGroupId
                                    }
                                ]
                            },
                            {
                                'FromPort': int(port),
                                'ToPort': int(port),
                                'IpProtocol': 'udp',
                                'UserIdGroupPairs': [
                                    {
                                        'Description': f'Allow udp {port} to {secGroupId}',
                                        'GroupId': secGroupId
                                    }
                                ]
                            }
                        ],
                        TagSpecifications=[
                            {
                                'ResourceType': 'security-group-rule',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': f'{sgName}{secGroupId}{port}'
                                    },
                                    {
                                        'Key': 'CreatedBy',
                                        'Value': createdBy
                                    },
                                    {
                                        'Key': 'CreatedAt',
                                        'Value': createdAt
                                    },
                                    {
                                        'Key': 'CreatedWith',
                                        'Value': 'Lightspin ECE'
                                    }
                                ]
                            }
                        ]
                    )
                else:
                    ec2.authorize_security_group_ingress(
                        GroupId=secGroupId,
                        IpPermissions=[
                            {
                                'FromPort': int(port),
                                'ToPort': int(port),
                                'IpProtocol': 'tcp',                            
                                'UserIdGroupPairs': [
                                    {
                                        'Description': f'Allow tcp {port} to {secGroupId}',
                                        'GroupId': secGroupId
                                    }
                                ]
                            }
                        ],
                        TagSpecifications=[
                            {
                                'ResourceType': 'security-group-rule',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': f'{sgName}{secGroupId}{port}'
                                    },
                                    {
                                        'Key': 'CreatedBy',
                                        'Value': createdBy
                                    },
                                    {
                                        'Key': 'CreatedAt',
                                        'Value': createdAt
                                    },
                                    {
                                        'Key': 'CreatedWith',
                                        'Value': 'Lightspin ECE'
                                    }
                                ]
                            }
                        ]
                    )

            # Adding TCP 443 (HTTPS) from the internet which is required for patching and agent communications
            ec2.authorize_security_group_ingress(
                GroupId=secGroupId,
                IpPermissions=[
                    {
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpProtocol': 'tcp',
                        'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0',
                                'Description': f'Allow tcp 443 to Internet'
                            }
                        ]
                    }
                ],
                TagSpecifications=[
                    {
                        'ResourceType': 'security-group-rule',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': f'{sgName}Internet{port}'
                            },
                            {
                                'Key': 'CreatedBy',
                                'Value': createdBy
                            },
                            {
                                'Key': 'CreatedAt',
                                'Value': createdAt
                            },
                            {
                                'Key': 'CreatedWith',
                                'Value': 'Lightspin ECE'
                            }
                        ]
                    }
                ]
            )
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)

        print(f'Finished creating {sgName} and adding all required Rule Authorizations')

        return secGroupId

    def encryption_key_factory(cluster_name):
        '''
        This function is responsible for creating a KMS Key to use with EKS Secrets Envelope Encryption as well as Nodegroup (EC2) EBS Encryption
        we will attach a proper Key Policy later
        '''
        kms = boto3.client('kms')
        sts = boto3.client('sts')

        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        # STS is also used for the Account ID to interpolate ARNs which will be created later
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        print(f'Creating KMS CMK for encryption operations')

        # The first time we create the Key we must not attach a policy as the Roles we need to give permission to do not exist yet (nodegroup & cluster IAM role)
        # it will attach a default policy that allows our entire AWS Account access - this is good so we can override it later
        try:
            kmsKeyArn = kms.create_key(
                Description=f'Used for EKS Envelope Encryption and EBS Volume Encryption for EKS Cluster {cluster_name} - Created by Lightspin ECE',
                # Default values for AES-256/GCM Keys. Being verbose in case AWS ever changes the default values of these
                KeyUsage='ENCRYPT_DECRYPT',
                KeySpec='SYMMETRIC_DEFAULT',
                Origin='AWS_KMS',
                Tags=[
                    {
                        'TagKey': 'Name',
                        'TagValue': f'{cluster_name}-EKS-CMK'
                    },
                    {
                        'TagKey': 'CreatedBy',
                        'TagValue': createdBy
                    },
                    {
                        'TagKey': 'CreatedAt',
                        'TagValue': createdAt
                    },
                    {
                        'TagKey': 'CreatedWith',
                        'TagValue': 'Lightspin ECE'
                    }
                ]
            )['KeyMetadata']['Arn']
        except KeyError as ke:
            print(f'Error encountered: {ke}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.ParamValidationError as pe:
            print(f'Error encountered: {pe}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)

        return kmsKeyArn
    
    def create_cluster(cluster_name, kubernetes_version, cluster_role_name, subnet_ids, vpc_id, additional_ports):
        '''
        This function uses the EKS Boto3 Client to create a cluster, taking inputs from main.py to determing naming & Encryption
        '''
        eks = boto3.client('eks')
        sts = boto3.client('sts')

        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        # Call `create_cluster_svc_role` to create or re-use the EKS cluster service IAM role
        clusterRoleArn = ClusterManager.create_cluster_svc_role(cluster_role_name)

        # Call `cluster_security_group_factory` to create or re-use an EKS cluster security group that allows minimum necessary comms intra-VPC
        securityGroupId = ClusterManager.cluster_security_group_factory(cluster_name, vpc_id, additional_ports)

        # Call `encryption_key_factory` to create a KMS Key ARN. Simple! (We'll add the Key Policy later)
        kmsKeyArn = ClusterManager.encryption_key_factory(cluster_name)

        try:
            # Call to create cluster
            r = eks.create_cluster(
                name=cluster_name,
                version=str(kubernetes_version),
                roleArn=clusterRoleArn,
                resourcesVpcConfig={
                    'subnetIds': subnet_ids,
                    'securityGroupIds': [securityGroupId],
                    'endpointPublicAccess': False,
                    'endpointPrivateAccess': True
                },
                logging={
                    'clusterLogging': [
                        {   
                            # all Logging types are enabled here
                            'types': ['api','audit','authenticator','controllerManager','scheduler'],
                            'enabled': True
                        }
                    ]
                },
                encryptionConfig=[
                    {
                        'resources': [
                            'secrets'
                        ],
                        'provider': {
                            'keyArn': kmsKeyArn
                        }
                    }
                ],
                tags={
                    'Name': cluster_name,
                    'CreatedBy': createdBy,
                    'CreatedAt': createdAt,
                    'CreatedWith': 'Lightspin ECE'
                }
            )

            # Establish provided EKS Waiter() for cluster to come up
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Waiter.ClusterActive
            print(f'Waiting for your Cluster to come online')

            waiter = eks.get_waiter('cluster_active')

            waiter.wait(
                name=cluster_name,
                WaiterConfig={
                    'Delay': 30,
                    'MaxAttempts': 40
                }
            )

            finalClusterName = str(r['cluster']['name'])

            print(f'EKS Cluster {finalClusterName} is now live')
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.WaiterError as we:
            print(f'Error encountered: {we}')
            RollbackManager.rollback_from_cache(cache=cache)

        del eks
        del sts
        del createdAt
        del createdBy
        del r
        del waiter

        return finalClusterName, securityGroupId, kmsKeyArn, clusterRoleArn

    def generate_nodegroup_bootstrap(bucket_name, cluster_name, mde_on_nodes, ami_os):
        '''
        This function generates EC2 UserData (in Base64) to be passed to the `create_launch_template` Function for creating a custom
        launch template that uses custom AMIs passed in main.py or defaults to the EKS-optimized AMI for Ubuntu 20.04LTS corresponding
        to the K8s verson used. This function parses the S3 Bucket from main.py which stores the MDE activation scripts, if that is configured.

        Additionally, required information is retrieved from the EKS Cluster to provide to the bootstrap script included by
        default in EKS-optimized AMIs. In this case, we will need the CA and API Server URL
        Details: https://aws.amazon.com/blogs/containers/introducing-launch-template-and-custom-ami-support-in-amazon-eks-managed-node-groups/

        WTF is `set -ex`? https://askubuntu.com/questions/346900/what-does-set-e-do
        '''
        eks = boto3.client('eks')

        print(f'Retrieving Certificate Authority and API Server URL information for bootstrap script')

        # DescribeCluster and pull necessary values to set as env vars within the bootstrap
        c = eks.describe_cluster(name=cluster_name)
        eksApiServerUrl = str(c['cluster']['endpoint'])
        eksB64ClusterCa = str(c['cluster']['certificateAuthority']['data'])

        # Support for IMDSv2 Tokens for reaching metadata service
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-ex-7

        # MDE Installation Scripts: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/linux-install-manually?view=o365-worldwide
        if mde_on_nodes == 'True':
            # Ubuntu
            if ami_os == 'ubuntu':
                script = f'''#!/bin/bash
                set -ex
                B64_CLUSTER_CA={eksB64ClusterCa}
                API_SERVER_URL={eksApiServerUrl}
                /etc/eks/bootstrap.sh {cluster_name} --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL
                apt update
                apt upgrade -y
                apt install -y curl python3 python3-pip libplist-utils gpg apt-transport-https zip unzip
                curl -o microsoft.list https://packages.microsoft.com/config/ubuntu/20.04/prod.list
                mv ./microsoft.list /etc/apt/sources.list.d/microsoft-prod.list
                curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
                apt update
                apt install -y mdatp
                aws s3 cp s3://{bucket_name}/mdatp/WindowsDefenderATPOnboardingPackage.zip .
                unzip WindowsDefenderATPOnboardingPackage.zip
                python3 MicrosoftDefenderATPOnboardingLinuxServer.py
                mdatp threat policy set --type potentially_unwanted_application --action block
                mdatp config network-protection enforcement-level --value block
                mdatp config real-time-protection --value enabled
                TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
                INSTANCE_ID=$(curl -H 'X-aws-ec2-metadata-token: $TOKEN' -v http://169.254.169.254/latest/meta-data/instance-id)
                mdatp edr tag set --name GROUP --value $INSTANCE_ID
                '''
            # Amazon Linux 2
            else:
                script = f'''#!/bin/bash
                set -ex
                B64_CLUSTER_CA={eksB64ClusterCa}
                API_SERVER_URL={eksApiServerUrl}
                /etc/eks/bootstrap.sh {cluster_name} --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL
                yum update -y
                yum-config-manager --add-repo=https://packages.microsoft.com/config/rhel/7/prod.repo
                rpm --import http://packages.microsoft.com/keys/microsoft.asc
                yum install mdatp -y
                aws s3 cp s3://{bucket_name}/mdatp/WindowsDefenderATPOnboardingPackage.zip .
                unzip WindowsDefenderATPOnboardingPackage.zip
                python3 MicrosoftDefenderATPOnboardingLinuxServer.py
                mdatp threat policy set --type potentially_unwanted_application --action block
                mdatp config network-protection enforcement-level --value block
                mdatp config real-time-protection --value enabled
                TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
                INSTANCE_ID=$(curl -H 'X-aws-ec2-metadata-token: $TOKEN' -v http://169.254.169.254/latest/meta-data/instance-id)
                mdatp edr tag set --name GROUP --value $INSTANCE_ID
                '''
        else:
            # No need for MDE in this one, create a regular script
            # Ubuntu
            if ami_os == 'ubuntu':
                script = f'''#!/bin/bash
                set -ex
                B64_CLUSTER_CA={eksB64ClusterCa}
                API_SERVER_URL={eksApiServerUrl}
                /etc/eks/bootstrap.sh {cluster_name} --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL
                apt update
                apt upgrade -y
                '''
            # Amazon Linux 2
            else:
                script = f'''#!/bin/bash
                set -ex
                B64_CLUSTER_CA={eksB64ClusterCa}
                API_SERVER_URL={eksApiServerUrl}
                /etc/eks/bootstrap.sh {cluster_name} --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL
                yum update -y
                '''

        # Base64 encode the bootstrap script
        userData = base64.b64encode(script.encode()).decode('ascii')

        del eks
        del c
        del eksB64ClusterCa
        del eksApiServerUrl

        return userData

    def create_launch_template(cluster_name, kubernetes_version, ami_id, bucket_name, launch_template_name, kms_key_arn, securityGroupId, ebs_volume_size, instance_type, mde_on_nodes, ami_os, ami_architecture):
        '''
        This function creates an EC2 Launch Template using encryption and AMI data supplied from main.py and passes it to the `builder` function
        where final EKS Nodegroup creation takes place
        '''
        # This is for creating the Launch Template used by EKS to launch Managed Node Groups with a custom AMI & bootstrap script
        ec2 = boto3.client('ec2')
        sts = boto3.client('sts')
        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())

        # Pull latest AMI ID for EKS-optimized Ubuntu 20.04LTS for specified K8s Version in main.py
        amiId = ClusterManager.get_latest_eks_optimized_ubuntu(kubernetes_version, ami_id, ami_os, ami_architecture)

        # Retrieve Base64 metadata from bootstrap generation function - this will download and install MDE (MDATP) from files in the S3 bucket specified in main.py if --mde_on_nodes is true. Will use ami_os arguements to create different UserData as well
        userData = ClusterManager.generate_nodegroup_bootstrap(bucket_name, cluster_name, mde_on_nodes, ami_os)

        # For IMDSv2 - keeping this outside for eventual modification of hop limits?
        metadataOptions = {
            'HttpTokens': 'required',
            'HttpPutResponseHopLimit': 2,
            'HttpEndpoint': 'enabled'
        }

        try:
            r = ec2.create_launch_template(
                DryRun=False,
                LaunchTemplateName=launch_template_name,
                VersionDescription=f'Created by the EKS Creation Engine on {createdAt}',
                LaunchTemplateData={
                    'EbsOptimized': False,
                    'BlockDeviceMappings': [
                        {
                            'DeviceName': '/dev/sda1',
                            'Ebs': {
                                'Encrypted': True,
                                'DeleteOnTermination': True,
                                'KmsKeyId': kms_key_arn,
                                'VolumeSize': int(ebs_volume_size),
                                'VolumeType': 'gp2'
                            }
                        }
                    ],
                    'ImageId': amiId,
                    'InstanceType': instance_type,
                    'UserData': str(userData),
                    'SecurityGroupIds': [securityGroupId],
                    'MetadataOptions': metadataOptions,
                    'TagSpecifications': [
                        {
                            'ResourceType': 'instance',
                            'Tags': [
                                {
                                    'Key': 'Name',
                                    'Value': str(f'{launch_template_name}Node')
                                },
                                {
                                    'Key': 'CreatedBy',
                                    'Value': createdBy
                                },
                                {
                                    'Key': 'CreatedAt',
                                    'Value': createdAt
                                },
                                {
                                    'Key': 'CreatedWith',
                                    'Value': 'Lightspin ECE'
                                }
                            ]
                        },
                        {
                            'ResourceType': 'volume',
                            'Tags': [
                                {
                                    'Key': 'Name',
                                    'Value': str(f'{launch_template_name}Node')
                                },
                                {
                                    'Key': 'CreatedBy',
                                    'Value': createdBy
                                },
                                {
                                    'Key': 'CreatedAt',
                                    'Value': createdAt
                                },
                                {
                                    'Key': 'CreatedWith',
                                    'Value': 'Lightspin ECE'
                                }
                            ]
                        }
                    ]
                }
            )

            launchTemplateId = str(r['LaunchTemplate']['LaunchTemplateId'])
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)
        except Exception as e:
            print(f'Error encountered: {e}')
            RollbackManager.rollback_from_cache(cache=cache)

        return launchTemplateId
    
    def builder(kubernetes_version, bucket_name, ebs_volume_size, ami_id, instance_type, cluster_name, cluster_role_name, nodegroup_name, nodegroup_role_name, launch_template_name, vpc_id, subnet_ids, node_count, mde_on_nodes, additional_ports, falco_bool, falco_sidekick_destination_type, falco_sidekick_destination, ami_os, ami_architecture, datadog_api_key, datadog_bool, addtl_auth_principals):
        '''
        This function is the 'brain' that controls creation and calls the required functions to build infrastructure and services (EKS, EC2, IAM).
        This function also stores all required arguments into cache to facilitate rollbacks upon errors
        '''

        # Write argument variables that are directly used for infrastructure creation to cache
        # Assemble names for Security Groups (these will be replicated everywhere but not passed around to minimize **kwargs bloat)
        cacheDict = {
            'ClusterName': cluster_name,
            'ClusterRoleName': cluster_role_name,
            'NodegroupName': nodegroup_name,
            'NodegroupRoleName': nodegroup_role_name,
            'LaunchTemplateName': launch_template_name
        }
        cache.append(cacheDict)

        print(f'Cache loaded with necessary rollback variables.')

        eks = boto3.client('eks')
        sts = boto3.client('sts')
        kms = boto3.client('kms')
        iam = boto3.client('iam')
        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()['Arn'])
        createdAt = str(datetime.utcnow())
        acctId = str(sts.get_caller_identity()['Account'])

        # Create an EKS Cluster by calling `create_cluster` - this will take the longest, and if it fails, then other infrastructure won't be created
        # the positional selectors are for when you return multiple values, they are bundled in a tuple, and have to be accessed in the order they're provided
        callClusterManager = ClusterManager.create_cluster(cluster_name, kubernetes_version, cluster_role_name, subnet_ids, vpc_id, additional_ports)
        clusterName = callClusterManager[0]
        securityGroupId = callClusterManager[1]
        kms_key_arn = callClusterManager[2]
        clusterRoleArn = callClusterManager[3]

        # Passes the S3 Bucket name to the `create_managed_nodegroup_role` function which in turn passes it to the `create_managed_nodegroup_s3_policy`
        # function which allows your Nodegroups to pull artifacts from S3 as part of bootstrapping
        nodegroupRoleArn = ClusterManager.create_managed_nodegroup_role(bucket_name, nodegroup_role_name, mde_on_nodes)

        # Now we can attach our proper Key Policy to the KMS Key since we now have all Roles ready

        # Extremely stupid workaround to assemble an upstream Role ARN from yhe "createdBy" variable just in case your ARN returned from STS GetCallerIdentity is a session ARN
        # for Assumed Roles. Despite the fact AWS documentation says that an Assumed-role session principal is supported by Resource-based policies like a KMS Key policy
        # (docs here https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-role-session) it returns a malformed policy error
        # due to the regex that is used underneath Botocore or AWS APIs....presumably
        # So this tries to create an ARN of the IAM Role you assumed (or transparently assumed if you are using WorkSpaces, Cloud9 or SSM Hybrid Activations or otherwise)
        # It is extremely stupid...YMMV for deletion
        # arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/ROLE_SESSION_NAME
        seshRoleRegex = re.compile('assumed-role')
        seshRoleCheck = seshRoleRegex.search(createdBy)
        # On match to Regex do stupid stuff >:(
        if seshRoleCheck:
            print(f'Your ARN from STS AssumeRole {createdBy} matches a temporary Session ARN, attempting to find your upstream IAM Role')
            roleNameSplit = createdBy.split('/')[1]
            createdByRoleArn = f'arn:aws:iam::{acctId}:role/{roleNameSplit}'
            print(f'Your Role ARN upstream to your session was determined as {createdByRoleArn}')
        else:
            # If you're not an assumed Role you're just a User or a Role and should be fine??
            createdByRoleArn = createdBy

        # Setup a modified version of the Default KMS Policy, eliminating some Conditional statements to allow Autoscaling, EKS, and EC2 to use the key and set Grants
        # First, attempt to create the SLR for the Autoscaling group if it does not exist, see: https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html
        try:
            r = iam.create_service_linked_role(AWSServiceName='autoscaling.amazonaws.com')
            slrRole = str(r['Role']['RoleName'])
            print(f'Created Service-linked Role for Autoscaling called {slrRole}')
        except Exception as e:
            if str(e) == 'An error occurred (InvalidInput) when calling the CreateServiceLinkedRole operation: Service role name AWSServiceRoleForAutoScaling has been taken in this account, please try a different suffix.':
                pass
            else:
                print(f'Error encountered: {e}')
                RollbackManager.rollback_from_cache(cache=cache)

        # Then check if there are any additional authorized principals specified for the cluster to add to the below static list of principals

        # Static list of who is *supposed* to have access
        kmsAuthZPrincipals = [
            clusterRoleArn,
            nodegroupRoleArn,
            createdByRoleArn,
            f'arn:aws:iam::{acctId}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling'
        ]

        # Check if additional AuthZ IAM Principals are even provided. If so, add them to the list if they're not there already
        if addtl_auth_principals:
            for arn in addtl_auth_principals:
                if arn not in kmsAuthZPrincipals:
                    kmsAuthZPrincipals.append(arn)

        keyPolicyJson = {
            'Version':'2012-10-17',
            'Id':'ecekeypolicy',
            'Statement': [
                # full key usage by whoever creates the key
                {
                    'Sid': 'Key Creator Admin',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': createdByRoleArn
                    },
                    'Action':'kms:*',
                    'Resource':'*'
                },
                # This allows usage of the key by the Cluster & Nodegroup and aws-managed service principals
                # Creator is added throughout as well
                # AWS Auto Scaling service role is added per: https://docs.aws.amazon.com/autoscaling/ec2/userguide/key-policy-requirements-EBS-encryption.html
                {
                    'Sid': 'Allow use of the key',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': kmsAuthZPrincipals,
                        'Service': [
                            'autoscaling.amazonaws.com',
                            'ec2.amazonaws.com'
                        ]
                    },
                    'Action': [
                        'kms:Encrypt',
                        'kms:Decrypt',
                        'kms:ReEncrypt*',
                        'kms:GenerateDataKey*',
                        'kms:DescribeKey'
                    ],
                    'Resource': '*'
                },
                {
                    'Sid': 'Allow attachment of persistent resources',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': kmsAuthZPrincipals,
                        'Service': [
                            'autoscaling.amazonaws.com',
                            'ec2.amazonaws.com'
                        ]
                    },
                    'Action': [
                        'kms:CreateGrant',
                        'kms:ListGrants',
                        'kms:RevokeGrant'
                    ],
                    'Resource': '*'
                }
            ]
        }

        # For whatever reason, role propagation is a bit delayed with registration on the KMS Resource-based resource policy side
        # we will sleep for a few seconds on top of using waiters to make sure they propagate and avoid errors...
        print(f'Attaching Key Policy to KMS Key {kms_key_arn}')
        time.sleep(20)

        try:
            kms.put_key_policy(
                KeyId=kms_key_arn,
                PolicyName='default',
                Policy=json.dumps(keyPolicyJson)
            )
            print(f'Key Policy attached to {kms_key_arn}')
        except KeyError as ke:
            print(f'Error encountered: {ke}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.ParamValidationError as pe:
            print(f'Error encountered: {pe}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)
        
        # Passes various arguements to the `create_launch_template` which returns a Launch Template ID (of the latest version) to pass to the Nodegroup creation payload
        launchTemplateId = ClusterManager.create_launch_template(cluster_name, kubernetes_version, ami_id, bucket_name, launch_template_name, kms_key_arn, securityGroupId, ebs_volume_size, instance_type, mde_on_nodes, ami_os, ami_architecture)

        print(f'Creating Nodegroup {nodegroup_name} for Cluster {clusterName}')

        # Create and launch the Nodegroup
        try:
            eks.create_nodegroup(
                clusterName=clusterName,
                nodegroupName=nodegroup_name,
                scalingConfig={
                    'minSize': int(node_count),
                    'maxSize': int(node_count) * 2,
                    'desiredSize': int(node_count)
                },
                nodeRole=nodegroupRoleArn,
                subnets=subnet_ids,
                launchTemplate={
                    'id': launchTemplateId
                },
                capacityType='ON_DEMAND',
                tags={
                    'Name': nodegroup_name,
                    'CreatedBy': createdBy,
                    'CreatedAt': createdAt,
                    'CreatedWith': 'Lightspin ECE'
                }
            )

            # Await Nodegroups to come online
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Waiter.NodegroupActive
            waiter = eks.get_waiter('nodegroup_active')
            print(f'Awaiting EKS Nodegroup {nodegroup_name} to come online')

            waiter.wait(
                clusterName=clusterName,
                nodegroupName=nodegroup_name,
                WaiterConfig={
                    'Delay': 30,
                    'MaxAttempts': 80
                }
            )
        except botocore.exceptions.ClientError as error:
            print(f'Error encountered: {error}')
            RollbackManager.rollback_from_cache(cache=cache)
        except botocore.exceptions.WaiterError as we:
            print(f'Error encountered: {we}')
            RollbackManager.rollback_from_cache(cache=cache)

        print(f'Creation complete. Nodegroup {nodegroup_name} in Cluster {clusterName} is online')

        # Retrieve region for AWS CLI kubectl generation
        session = boto3.session.Session()
        awsRegion = session.region_name

        # Setup first time cluster connection with AWS CLI
        updateKubeconfigCmd = f'aws eks update-kubeconfig --region {awsRegion} --name {clusterName}'
        updateKubeconfigProc = subprocess.run(updateKubeconfigCmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(updateKubeconfigProc.stdout.decode('utf-8'))

        # If additional principals are required to be authorized, attempt to do so
        if addtl_auth_principals:
            for arn in addtl_auth_principals:
                # Split out the name part of the Role
                addtlRoleName = str(arn.split('/')[1])
                # Create a patch object to add into
                newAuthZScript=f'''ROLE="    - rolearn: {arn}\\n      username: {addtlRoleName}\\n      groups:\\n        - system:masters"
                kubectl get -n kube-system configmap/aws-auth -o yaml | awk "/mapRoles: \|/{{print;print \\"$ROLE\\";next}}1" > /tmp/aws-auth-patch.yml
                kubectl patch configmap/aws-auth -n kube-system --patch "$(cat /tmp/aws-auth-patch.yml)"
                '''

                newAuthZScriptProc = subprocess.run(newAuthZScript, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(newAuthZScriptProc.stdout.decode('utf-8'))

        # Send a call into plugins.ECEFalco
        if falco_bool == 'True':
            FalcoSetup.falco_initialization(
                cluster_name=clusterName, 
                falco_mode='Create',
                falco_sidekick_destination_type=falco_sidekick_destination_type, 
                falco_sidekick_destination=falco_sidekick_destination,
                datadog_api_key=datadog_api_key
            )
        # Send a call into plugins.ECEDatadog
        if datadog_bool == 'True':
            DatadogSetup.initialization(
                cluster_name=clusterName, 
                datadog_mode='Create',
                datadog_api_key=datadog_api_key
            )
        # Send a call into plugins.ECENonameSecurity
        # TODO!
        
'''
This Class handles all update tasks to the Clusters directly or by interacting with loaded Plugins. For instance, this Class will directly update Kubernetes Versions or Add Nodegroups.
This Class will call external Plugins in "creation" mode to install MDE, install DataDog, install Falco, and install Noname Security K8s Agents.
'''
class UpdateManager():

    def update_manager(cluster_name, nodegroup_name, kubernetes_version, mde_on_nodes, bucket_name, falco_bool, falco_sidekick_destination_type, falco_sidekick_destination, datadog_api_key, datadog_bool, update_k8s_version):
        '''
        This function controls all of the Update functions such as optional installation of additional sensors, updating the K8s version, and
        adding Nodegroups or Nodecounts into the Cluster.
        '''

        # Check if we need to perform a Version Bump
        if update_k8s_version == 'True':
            UpdateManager.update_kubernetes_version(
                cluster_name, 
                nodegroup_name,
                kubernetes_version
            )
        # Send a call into plugins.ECEFalco
        if falco_bool == 'True':
            FalcoSetup.falco_initialization(
                cluster_name=cluster_name, 
                falco_mode='Create',
                falco_sidekick_destination_type=falco_sidekick_destination_type, 
                falco_sidekick_destination=falco_sidekick_destination,
                datadog_api_key=datadog_api_key
            )
        # Send a call into plugins.ECEDatadog
        if datadog_bool == 'True':
            DatadogSetup.initialization(
                cluster_name=cluster_name, 
                datadog_mode='Create',
                datadog_api_key=datadog_api_key
            )
        # Send a call into plugins.ECENonameSecurity
        # TODO!
    
    def update_kubernetes_version(cluster_name, nodegroup_name, kubernetes_version):
        '''
        This function attempts to update existing Cluster and Nodegroup to a specified Kubernetes Version by invoking
        separate functions after a basic version match test
        '''

        eks = boto3.client('eks')

        # Lookup EKS Nodegroup to see if the specified K8s version from main.py matches, if they do not not attempt an upgrade
        existingNodegroupVersion = eks.describe_cluster(name=cluster_name,nodegroupName=nodegroup_name)['nodegroup']['version']
        if existingNodegroupVersion == kubernetes_version:
            print(f'EKS Nodegroup {nodegroup_name} in Cluster {cluster_name} is already at Kubernetes version {kubernetes_version}. Not attempting an Update.')
        else:
            print(f'EKS Nodegroup {nodegroup_name} in Cluster {cluster_name} is viable to update from Kubernetes version {existingNodegroupVersion} to {kubernetes_version}')
            UpdateManager.update_nodegroup_kubernetes_version(cluster_name, nodegroup_name, kubernetes_version)
        
        # Lookup EKS Cluster to see if the specified K8s version from main.py matches, if they do not not attempt an upgrade
        existingClusterVersion = eks.describe_cluster(name=cluster_name)['cluster']['version']
        if existingClusterVersion == kubernetes_version:
            print(f'EKS Cluster {cluster_name} is already at Kubernetes version {kubernetes_version}. Not attempting an Update.')
        else:
            print(f'EKS Cluster {cluster_name} is viable to update from Kubernetes version {existingClusterVersion} to {kubernetes_version}')
            UpdateManager.update_cluster_kubernetes_version(cluster_name, kubernetes_version)

    def update_nodegroup_kubernetes_version(cluster_name, nodegroup_name, kubernetes_version):
        '''
        This function carries out the update and waiter for EKS Nodegroup K8s version bumps
        '''
        print(f'Updating Kubernetes version for EKS Nodegroup {nodegroup_name} in EKS Cluster {cluster_name}')

        eks = boto3.client('eks')

        # Update the Nodegroup K8s version and parse the EKS Update ID for later use
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.update_nodegroup_version
        r = eks.update_nodegroup_version(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            version=kubernetes_version
        )
        updateId = str(r['update']['id'])

        print(f'Monitoring EKS Update ID {updateId} for failure or success state.')

        # Use a `while True` loop and 15 second sleeps to watch the update progress of the cluster
        # Break the loop on Success, continue on 'InProgress', and exit code 2 on failures or cancellations
        while True:
            d = eks.describe_update(
                name=cluster_name,
                updateId=updateId,
                nodegroupName=nodegroup_name
            )
            updateStatus = str(d['update']['status'])
            # if/else logic time
            if updateStatus == 'Successful':
                print(f'Nodegroup {nodegroup_name} in Cluster {cluster_name} has been successfully updated.')
                break
            elif updateStatus == 'Failed' or 'Cancelled':
                errorMessage = str(d['update']['errors'])
                print(f'Nodegroup {nodegroup_name} in Cluster {cluster_name} update has been cancelled or has failed!')
                print(f'Error message: {errorMessage}')
                sys.exit(2)
            else:
                print(f'Awaiting update status change for 30 more seconds...')
                del d
                del updateStatus
                time.sleep(30)
                continue

    def update_cluster_kubernetes_version(cluster_name, kubernetes_version):
        '''
        This function carries out the update and waiter for EKS Cluster K8s version bumps
        '''
        print(f'Updating Kubernetes version for EKS Cluster {cluster_name}')

        eks = boto3.client('eks')

        # Update the Nodegroup K8s version and parse the EKS Update ID for later use
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.update_nodegroup_version
        r = eks.update_nodegroup_version(
            clusterName=cluster_name,
            version=kubernetes_version
        )
        updateId = str(r['update']['id'])

        print(f'Monitoring EKS Update ID {updateId} for failure or success state.')

        # Use a `while True` loop and 15 second sleeps to watch the update progress of the cluster
        # Break the loop on Success, continue on 'InProgress', and exit code 2 on failures or cancellations
        while True:
            d = eks.describe_update(
                name=cluster_name,
                updateId=updateId
            )
            updateStatus = str(d['update']['status'])
            # if/else logic time
            if updateStatus == 'Successful':
                print(f'Cluster {cluster_name} has been successfully updated.')
                break
            elif updateStatus == 'Failed' or 'Cancelled':
                errorMessage = str(d['update']['errors'])
                print(f'Cluster {cluster_name} update has been cancelled or has failed!')
                print(f'Error message: {errorMessage}')
                sys.exit(2)
            else:
                print(f'Awaiting update status change for 15 more seconds...')
                del d
                del updateStatus
                time.sleep(15)
                continue

'''
Despite it's name, this Class contains methods to conduct emergency deletions (rollback) from Cache as well as normal deletions from main.py commands
this is purely for Create mode, other Classes may have their own self-contained rollback mechanism.
'''
class RollbackManager():

    def scheduled_deletion(nodegroup_name, cluster_name, cluster_role_name, nodegroup_role_name, launch_template_name):
        '''
        This function performs a graceful, scheduled deletion of all resources - or attempts to at least
        '''
        eks = boto3.client('eks')

        print(f'Deletion command received. Attempting to delete all resources')

        # Retrieve the Security Groups from the Cluster to delete, as they are not provided as arguments and cannot be guessed (ID's and all that...)
        sgList = []
        for sg in eks.describe_cluster(name=cluster_name)['cluster']['resourcesVpcConfig']['securityGroupIds']:
            sgList.append(sg)

        # First, attempt to delete Nodegroup
        RollbackManager.delete_nodegroup(
            nodegroup_name=nodegroup_name,
            cluster_name=cluster_name
        )

        # Then, try to find the Cluster KMS Key and attempt to delete it
        try:
            kmsKeyArn= eks.describe_cluster(name=cluster_name)['cluster']['encryptionConfig'][0]['provider']['keyArn']
        except Exception:
            kmsKeyArn = None
        
        if kmsKeyArn != None:
            RollbackManager.delete_kms_key(
                kms_key_arn=kmsKeyArn
            )

        # Next, attempt to delete Cluster
        RollbackManager.delete_cluster(
            cluster_name=cluster_name
        )

        # Next, attempt to delete all related IAM
        RollbackManager.delete_eks_iam(
            cluster_role_name=cluster_role_name,
            nodegroup_role_name=nodegroup_role_name
        )

        # Next, attempt to delete the EC2 Launch Template
        RollbackManager.delete_launch_template(
            launch_template_name=launch_template_name
        )

        # Finally, loop the retrieved SGs and then delete them
        for sg in sgList:
            print(f'Trying to delete EC2 Security Group {sg}')
            RollbackManager.delete_security_groups(
                cluster_security_group_id=sg
            )

        print(f'Deletion complete. Confirm resource deletion in Console in case of errors')

    def rollback_from_cache(cache):
        '''
        This function is invoked during any error encountered during the creation process in the `ClusterManager` Class - a Cache is passed and any resource
        that would be created is attempted to be deleted as the failures can occur at any stage
        '''

        print(f'Error encountered! Rollback from cache initiated.')
        eks = boto3.client('eks')

        # pull vars from Cache
        nodegroupName = str(cache[0]['NodegroupName'])
        clusterName = str(cache[0]['ClusterName'])
        clusterRoleName = str(cache[0]['ClusterRoleName'])
        nodegroupRoleName = str(cache[0]['NodegroupRoleName'])
        launchTemplateName = str(cache[0]['LaunchTemplateName'])
        clusterSgId = str(cache[1]['ClusterSecurityGroupId'])

        # First, attempt to delete Nodegroup
        RollbackManager.delete_nodegroup(
            nodegroup_name=nodegroupName,
            cluster_name=clusterName
        )

        # Then, try to find the Cluster KMS Key and attempt to delete it
        try:
            kmsKeyArn= eks.describe_cluster(name=clusterName)['cluster']['encryptionConfig'][0]['provider']['keyArn']
        except Exception:
            kmsKeyArn = None

        if kmsKeyArn != None:
            RollbackManager.delete_kms_key(
                kms_key_arn=kmsKeyArn
            )

        # Next, attempt to delete Cluster
        RollbackManager.delete_cluster(
            cluster_name=clusterName
        )

        # Next, attempt to delete all related IAM
        RollbackManager.delete_eks_iam(
            cluster_role_name=clusterRoleName,
            nodegroup_role_name=nodegroupRoleName
        )

        # Next, attempt to delete the EC2 Launch Template
        RollbackManager.delete_launch_template(
            launch_template_name=launchTemplateName
        )

        # Finally, delete the Security Groups
        RollbackManager.delete_security_groups(
            cluster_security_group_id=clusterSgId
        )

        print(f'Rollback complete. Confirm resource deletion in Console in case of errors')

        del cache
        sys.exit(2)

    def delete_nodegroup(cluster_name, nodegroup_name):
        '''
        This function attempts to delete an EKS Nodegroup
        '''
        print(f'Attempting to delete EKS Nodegroup {nodegroup_name} in EKS Cluster {cluster_name}.')

        eks = boto3.client('eks')

        try:
            eks.delete_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name
            )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        # Wait for the Nodegroup to be fully deleted before deleting the Cluster
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Waiter.NodegroupDeleted
        print(f'Awaiting deletion of EKS Nodegroup {nodegroup_name} in EKS Cluster {cluster_name}.')

        waiter = eks.get_waiter('nodegroup_deleted')

        waiter.wait(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 40
            }
        )

        print(f'EKS Nodegroups rolled back.')

        del eks

    def delete_cluster(cluster_name):
        '''
        This function attempts to delete an EKS Cluster
        '''
        print(f'Attempting to delete EKS Cluster {cluster_name}.')

        eks = boto3.client('eks')

        try:
            eks.delete_cluster(
                name=cluster_name
            )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        # Wait for the Cluster to be fully deleted before deleting the IAM Roles
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Waiter.ClusterDeleted
        print(f'Awaiting deletion of EKS Cluster {cluster_name}.')

        waiter = eks.get_waiter('cluster_deleted')

        waiter.wait(
            name=cluster_name,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 123
            }
        )

        print(f'EKS Clusters rolled back.')

        del eks

    def delete_eks_iam(cluster_role_name, nodegroup_role_name):
        '''
        This function attempts to delete all related IAM entities for EKS (Cluster roles, Nodegroup roles, Nodegroup policies)
        '''
        print(f'Attempting to delete various IAM entities. IAM Roles {cluster_role_name} and {nodegroup_role_name} and IAM Policy {nodegroup_role_name}Policy.')

        iam = boto3.client('iam')
        sts = boto3.client('sts')
        account = sts.get_caller_identity()['Account']

        # Assemble an IAM Policy ARN for nodegroup
        nodegroupS3PolicyArn = f'arn:aws:iam::{account}:policy/{nodegroup_role_name}Policy'

        # Find and detach all policies from the Cluster Role
        try:
            for policy in iam.list_attached_role_policies(RoleName=cluster_role_name)['AttachedPolicies']:
                policyArn = str(policy['PolicyArn'])
                iam.detach_role_policy(
                    RoleName=cluster_role_name,
                    PolicyArn=policyArn
                )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        # Detach all Policies from Nodegroup cluster
        try:
            for policy in iam.list_attached_role_policies(RoleName=nodegroup_role_name)['AttachedPolicies']:
                policyArn = str(policy['PolicyArn'])
                iam.detach_role_policy(
                    RoleName=nodegroup_role_name,
                    PolicyArn=policyArn
                )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        try:
            iam.delete_policy(PolicyArn=nodegroupS3PolicyArn)
        except botocore.exceptions.ClientError as error:
            print(error)

        try:
            iam.delete_role(RoleName=cluster_role_name)
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        try:
            iam.delete_role(RoleName=nodegroup_role_name)
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')
        

        print(f'IAM Roles and Policies rolled back.')

        del iam
        del sts
        del account
        del nodegroupS3PolicyArn

    def delete_launch_template(launch_template_name):
        '''
        This function attempts to delete the EC2 Launch Template used for EKS Nodegroups
        '''
        print(f'Attempting to delete EC2 launch template {launch_template_name}.')

        ec2 = boto3.client('ec2')

        try:
            ec2.delete_launch_template(
                DryRun=False,
                LaunchTemplateName=launch_template_name
            )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        print(f'EC2 Launch Templates rolled back.')

        del ec2

    def delete_security_groups(cluster_security_group_id):
        '''
        This function attempts to delete the EC2 Security Groups used for EKS Clusters and Nodegroups
        '''
        print(f'Attempting to delete EC2 Security Group {cluster_security_group_id}')

        ec2 = boto3.client('ec2')

        try:
            ec2.delete_security_group(GroupId=cluster_security_group_id)
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        print(f'Security Group rolled back')

        del ec2

    def delete_kms_key(kms_key_arn):
        '''
        This function attempts to delete the KMS Key used for EKS Envelope Encryption
        '''
        print(f'Attempting to delete KMS Key ARN {kms_key_arn}')

        kms = boto3.client('kms')

        try:
            kms.schedule_key_deletion(
                KeyId=kms_key_arn,
                PendingWindowInDays=7
            )
        except botocore.exceptions.ClientError as error:
            print(f'Rollback error encounter {error}')

        print(f'KMS Key rolled back')

        del kms