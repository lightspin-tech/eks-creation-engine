# This file is part of Lightspin EKS Creation Engine.
# SPDX-License-Identifier: Apache-2.0
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
#'License'); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
#'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import json
import subprocess
import sys
from datetime import datetime

import boto3
import botocore.exceptions

"""
This Class manages an end-to-end deployment of Falco and FalcoSidekick to EKS using Helm. This class can be called from ClusterManager (if flag is set) or called independently to setup Falco
"""


class FalcoSetup:
    def falco_initialization(
        cluster_name,
        falco_mode,
        falco_sidekick_destination_type,
        falco_sidekick_destination,
        datadog_api_key,
    ):
        """
        This function handles configuration of Falco and FalcoSidekick on a Cluster, whether in-line of an ECE Create or ECE SetupFalco `--mode` from main.py
        Depending on the destination configuration and mode, this function will either schedule deletion or creation of additional infrastructure and issue Helm
        commands to your cluster
        """
        print(f"Setting up Falco on {cluster_name}")

        if falco_mode == "Create":
            print(f"Setting up Falco on running Nodes for {cluster_name}")
            if falco_sidekick_destination_type == "SNS":
                # Create EKS Client
                eks = boto3.client("eks")

                # Create an empty list of Role ARNs to append Cluster & Node Roles to send to different functions
                roleArns = []

                # First, since we may have to work with existing Clusters that ECE did not setup, find all Nodegroups for the cluster and retrieve their Role ARNs
                # and add them to the static list above if they are not already there
                for nodegroup in eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]:
                    nodeRoleArn = eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=nodegroup
                    )["nodegroup"]["nodeRole"]
                    if nodeRoleArn not in roleArns:
                        roleArns.append(nodeRoleArn)

                # Retrieve Cluster Role Arn
                clusterRoleArn = eks.describe_cluster(name=cluster_name)["cluster"]["roleArn"]
                if clusterRoleArn not in roleArns:
                    roleArns.append(clusterRoleArn)

                topicArn = FalcoSetup.falco_sidekick_sns_iam_generator(
                    cluster_name=cluster_name,
                    falco_sidekick_destination=falco_sidekick_destination,
                    role_arns=roleArns,
                )

                # Install Falco
                # All commands for FalcoSidekick come from the Helm vars spec in the chart GitHub repo: https://github.com/falcosecurity/charts/tree/master/falcosidekick#configuration
                falcoHelmCmd = f"helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=false --set falcosidekick.config.aws.sns.topicarn={topicArn}"
                FalcoSetup.install_falco(falco_install_command=falcoHelmCmd)
            elif falco_sidekick_destination_type == "Slack":
                print(
                    f"Configuring Falco and FalcoSidekick to send runtime alerts to Slack Webhook {falco_sidekick_destination}"
                )

                # Install Falco
                falcoHelmCmd = f"helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=false --set falcosidekick.config.slack.webhookurl={falco_sidekick_destination}"
                FalcoSetup.install_falco(falco_install_command=falcoHelmCmd)
            elif falco_sidekick_destination_type == "Teams":
                print(
                    f"Configuring Falco and FalcoSidekick to send runtime alerts to Teams Webhook {falco_sidekick_destination}"
                )
                # Install Falco
                falcoHelmCmd = f"helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=false --set falcosidekick.config.teams.webhookurl={falco_sidekick_destination}"
                FalcoSetup.install_falco(falco_install_command=falcoHelmCmd)
            elif falco_sidekick_destination_type == "Datadog":
                print(
                    f"Configuring Falco and FalcoSidekick to send runtime alerts to Datadog Host {falco_sidekick_destination}"
                )
                # Install Falco
                falcoHelmCmd = f"helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=false --set falcosidekick.config.datadog.host={falco_sidekick_destination} --set falcosidekick.config.datadog.apikey={datadog_api_key}"
                FalcoSetup.install_falco(falco_install_command=falcoHelmCmd)
            else:
                print(f"Unsupported destination type provided, exiting")
                sys.exit(2)
        else:
            print(f"Rolling back Falco on running Nodes for {cluster_name}")
            FalcoSetup.falco_setup_rollback(cluster_name=cluster_name)

    def falco_sidekick_sns_iam_generator(cluster_name, falco_sidekick_destination, role_arns):
        """
        This function will create IAM Policies to attach to the Roles of EKS Clusters and Nodegroups being boostrapped for Falco if they are configured
        to send messages to SNS. It will invoke `falco_sidekick_sns_creation` to receive the Topic ARN for the SNS Topic (if one is not provided)
        """
        print(f"Configuring {cluster_name} Cluster and Nodegroup IAM Roles to communicate with SNS")

        sts = boto3.client("sts")
        iam = boto3.client("iam")

        # If the value for 'falco_sidekick_destination' is None, that means a SNS topic was not provided and needs to be setup
        if falco_sidekick_destination == None:
            topicArn = FalcoSetup.falco_sidekick_sns_creation(
                cluster_name=cluster_name, role_arns=role_arns
            )
        else:
            topicArn = falco_sidekick_destination

        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()["Arn"])
        createdAt = str(datetime.utcnow())

        # AWS Account ID
        acctId = str(sts.get_caller_identity()["Account"])

        # Bring in the list of Role ARNs to append Cluster & Node Roles into for attaching policies to
        roleArns = role_arns

        # Create the IAM Policy for SNS
        iamPolicyDoc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Snssid",
                    "Effect": "Allow",
                    "Action": ["sns:Publish", "sns:GetTopicAttributes", "sns:ListTopics"],
                    "Resource": [topicArn],
                }
            ],
        }

        policyName = f"{cluster_name}FalcoSidekick-SNSPublishPolicy"

        try:
            iam.create_policy(
                PolicyName=policyName,
                Path="/",
                PolicyDocument=json.dumps(iamPolicyDoc),
                Description=f"Allows EKS Cluster {cluster_name} and Nodegroups to send Falco alerts to SNS - Created by Lightspin ECE",
                Tags=[
                    {"Key": "Name", "Value": policyName},
                    {"Key": "CreatedBy", "Value": createdBy},
                    {"Key": "CreatedAt", "Value": createdAt},
                    {"Key": "CreatedWith", "Value": "Lightspin ECE"},
                ],
            )
            policyArn = f"arn:aws:iam::{acctId}:policy/{policyName}"
        except botocore.exceptions.ClientError as error:
            print(f"Error encountered: {error}")
            FalcoSetup.falco_setup_rollback(cluster_name=cluster_name)

        for role in roleArns:
            roleName = role.split("/")[1]
            try:
                iam.attach_role_policy(RoleName=roleName, PolicyArn=policyArn)
            except botocore.exceptions.ClientError as error:
                print(f"Error encountered: {error}")
                FalcoSetup.falco_setup_rollback(cluster_name=cluster_name)

        del sts
        del iam
        del createdAt
        del createdBy
        del acctId
        del iamPolicyDoc
        del policyName

        return topicArn

    def falco_sidekick_sns_creation(cluster_name, role_arns):
        """
        This function creates an SNS Topic and Topic Policy for use as a FalcoSidekick destination if a valid ARN is not provided for the 'SNS' destination type and returns
        the Topic Arn to the `falco_sidekick_sns_iam_generator()` function which this function is called from. Otherwise, this function does nothing if not called from `falco_initialization`
        """
        print(f"Creating SNS Topic to send Falco alerts to for {cluster_name}")

        sns = boto3.client("sns")
        sts = boto3.client("sts")

        # Use STS GetCallerIdentity and Datetime to generate CreatedBy and CreatedAt information for tagging
        createdBy = str(sts.get_caller_identity()["Arn"])
        createdAt = str(datetime.utcnow())

        # AWS Account ID
        acctId = str(sts.get_caller_identity()["Account"])

        # Bring in the list of Role ARNs to append Cluster & Node Roles into for adding Principal permissions to the SNS Topic Policy
        roleArns = role_arns

        # Create an SNS Topic
        # NOTE: In the future, need to add KMS along with EncryptionCreationEngine https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html
        topicName = f"{cluster_name}-FalcoSidekickTopic"

        try:
            topicArn = sns.create_topic(
                Name=topicName,
                Attributes={"DisplayName": topicName},
                Tags=[
                    {"Key": "Name", "Value": topicName},
                    {"Key": "CreatedBy", "Value": createdBy},
                    {"Key": "CreatedAt", "Value": createdAt},
                    {"Key": "CreatedWith", "Value": "Lightspin ECE"},
                ],
            )["TopicArn"]
        except botocore.exceptions.ClientError as error:
            print(f"Error encountered: {error}")
            FalcoSetup.falco_setup_rollback(cluster_name=cluster_name)

        # Create a SNS Topic Policy Doc to pass in as an SNS Attribute
        topicPolicyJson = {
            "Version": "2008-10-17",
            "Id": "ecepolicy",
            "Statement": [
                {
                    "Sid": "ecesid-pub",
                    "Effect": "Allow",
                    "Principal": {"AWS": roleArns},
                    "Action": ["SNS:Publish"],
                    "Resource": topicArn,
                },
                {
                    "Sid": "ecesid-sub",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["SNS:Subscribe"],
                    "Resource": topicArn,
                    "Condition": {"StringEquals": {"AWS:SourceOwner": acctId}},
                },
            ],
        }

        try:
            sns.set_topic_attributes(
                TopicArn=topicArn,
                AttributeName="Policy",
                AttributeValue=json.dumps(topicPolicyJson),
            )
        except botocore.exceptions.ClientError as error:
            print(f"Error encountered: {error}")
            FalcoSetup.falco_setup_rollback(cluster_name=cluster_name)

        del topicName
        del sns
        del sts
        del createdBy
        del createdAt
        del acctId

        return topicArn

    def install_falco(falco_install_command):
        """
        This function receives the final installation command from `falco_initialization` and will attempt to add the latest Falco Security Helm Charts and install
        Falco onto a new namespace on your EKS Cluster
        """
        print(f"Installing Falco and FalcoSidekick")

        # Use subprocess to add Falco Charts using Helm
        print(f"Adding Falco Helm Charts")
        falcoHelmChartAddCmd = (
            "helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update"
        )
        falcoHelmChartAddSubprocess = subprocess.run(
            falcoHelmChartAddCmd, shell=True, capture_output=True
        )
        falcoHelmChartAddMsg = str(falcoHelmChartAddSubprocess.stdout.decode("utf-8"))
        print(falcoHelmChartAddMsg)

        # Use subprocess to configure Falco and FalcoSidekick per initiation arguments from main.py
        print(f"Installing Falco and FalcoSidekick")
        installFalcoCmd = falco_install_command
        installFalcoSubprocess = subprocess.run(installFalcoCmd, shell=True, capture_output=True)
        installFalcoMsg = str(installFalcoSubprocess.stdout.decode("utf-8"))
        print(installFalcoMsg)

    # Rollback and manual deletes starts here
    def falco_setup_rollback(cluster_name):
        """
        This function handles rollback of resources just for Falco
        """

        sts = boto3.client("sts")
        acctId = str(sts.get_caller_identity()["Account"])
        iam = boto3.client("iam")
        sns = boto3.client("sns")
        # Retrieve region for AWS CLI kubectl generation
        session = boto3.session.Session()
        awsRegion = session.region_name

        # Create & Stage Policy & SNS Names (only used if ECE created them)
        policyName = f"{cluster_name}FalcoSidekick-SNSPublishPolicy"
        policyArn = f"arn:aws:iam::{acctId}:policy/{policyName}"
        topicName = f"{cluster_name}-FalcoSidekickTopic"
        topicArn = f"arn:aws:sns:{awsRegion}:{acctId}:{topicName}"

        # If an IAM Policy for SNS was created, attempt to detach it before deletion
        try:
            rolesAttachedToPolicy = iam.list_entities_for_policy(
                PolicyArn=policyArn, EntityFilter="Role", PolicyUsageFilter="PermissionsPolicy"
            )["PolicyRoles"]
            if rolesAttachedToPolicy:
                for role in rolesAttachedToPolicy:
                    roleName = str(role["RoleName"])
                    iam.detach_role_policy(RoleName=roleName, PolicyArn=policyArn)
        except botocore.exceptions.ClientError as error:
            print(error)
        except KeyError as ke:
            print(ke)

        # If an IAM Policy for SNS was created, attempt to delete it
        try:
            iam.delete_policy(PolicyArn=policyArn)
            print(f"Falco SNS Policy {policyArn} deleted")
        except botocore.exceptions.ClientError as error:
            print(error)

        # If an SNS Topic was created, attempt to delete it
        try:
            sns.delete_topic(TopicArn=topicArn)
            print(f"Falco SNS Topic {topicArn} deleted")
        except botocore.exceptions.ClientError as error:
            print(error)

        # Uninstall Falco from EKS
        falcoRemoveCmd = "helm uninstall falco"
        falcoRemoveSubprocess = subprocess.run(falcoRemoveCmd, shell=True, capture_output=True)
        falcoRemoveMsg = str(falcoRemoveSubprocess.stdout.decode("utf-8"))
        print(falcoRemoveMsg)

        print(f"Falco rollback complete.")
        sys.exit(2)
