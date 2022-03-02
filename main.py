# This file is part of Lightspin EKS Creation Engine.
# SPDX-License-Identifier: Apache-2.0
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import argparse
import json
import re
import subprocess
import sys

import boto3
import botocore
import termcolor
from art import text2art
from clint.textui import colored
from clint.textui import puts

from EksCreationEngine import ClusterManager
from EksCreationEngine import RollbackManager
from EksCreationEngine import UpdateManager
from plugins.ECEDatadog import DatadogSetup
from plugins.ECEFalco import FalcoSetup
from plugins.ECESecurity import SecurityAssessment


def print_logo():
    textArt = text2art("EKS   CREATION   ENGINE")
    print(termcolor.colored(textArt, "red"))
    puts(colored.red("CREATED BY THE LIGHTSPIN OFFICE OF THE CISO"))
    puts(
        colored.red(
            "For more information about Lightspin reach out to support@lightspin.io or visit us at https://lightspin.io"
        )
    )


def stay_dangerous():
    textArt = text2art("STAY   DANGEROUS")
    print(termcolor.colored(textArt, "red"))
    puts(colored.red("With Love, the Lightspin Office of the CISO"))


def create_preflight_check():
    """
    This function conducts a "preflight check" to ensure that required arguments are provided for the specified "Mode" before
    attempting to execute them.
    """
    print_logo()

    eks = boto3.client("eks")

    # Conditional check to ensure that AMI ID (if provided) matches regex
    amiId = args.ami_id
    if amiId != "SSM":
        # AMI Regex
        amiRegex = re.compile(
            "^(?:(?:ami)(?:-[a-zA-Z0-9]+)?\b|(?:[0-9]{1,3}\\.){3}[0-9]{1,3})(?:\\s*,\\s*(?:(?:ami)(?:-[a-zA-Z0-9]+)?\b|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}))*$"
        )
        # Attempt to match
        amiRegexCheck = amiRegex.search(amiId)
        if not amiRegexCheck:
            print(
                f"Improperly AMI ID provided, does not match regex, check value and submit request again"
            )
            sys.exit(2)

    # Check if an EKS Cluster exists for provided name
    try:
        eks.describe_cluster(name=clusterName)
    except botocore.exceptions.ClientError as error:
        # If we have an "ResourceNotFoundException" error it means the cluster doesnt exist - which is what we want
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            pass
        else:
            print(
                f"An EKS Cluster with the name {clusterName} already exists. Please specify another name and try again"
            )
            sys.exit(2)

    # Check if an EKS Nodegroup exists for provided name
    try:
        eks.describe_nodegroup(clusterName=clusterName, nodegroupName=nodegroupName)
    except botocore.exceptions.ClientError as error:
        # If we have an "ResourceNotFoundException" error it means the cluster/nodegroup doesnt exist - which is what we want
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            pass
        else:
            print(
                f"An EKS Nodegroup with the name {nodegroupName} already exists. Please specify another name and try again"
            )
            sys.exit(2)

    # Check for a provided VPC
    if vpcId == None:
        print(f"VPC ID is required for cluster creation. Please specify a VPC ID and try again.")
        sys.exit(2)

    # Check for non-empty lists for Subnets
    if args.subnets:
        pass
    else:
        print(f"Subnets need to be specified for cluster creation")
        sys.exit(2)

    # Ensure a S3 Bucket was provided if MDE installation is true
    if installMdeOnNodes == "True":
        if bucketName == None:
            print(
                f"S3 Bucket name was not provided. Please provide a valid S3 Bucket and try again"
            )
            sys.exit(2)

    # Ensure a Datadog API key is provided if Datadog installation is true
    if datadogBool == "True":
        if datadogApiKey == None:
            print(
                f"Datadog setup was specified but a Datadog API was not provided. Please provide a valid API key and try again."
            )
            sys.exit(2)

    # Print out creation specification - in the future this will be a "state file" for the cluster
    specDict = {
        "K8sVersion": k8sVersion,
        "S3BucketName": bucketName,
        "EBSVolumeSize": ebsVolumeSize,
        "AmiId": amiId,
        "InstanceType": instanceType,
        "ClusterName": clusterName,
        "ClusterRoleName": clusterRoleName,
        "NodegroupName": nodegroupName,
        "NodegroupRoleName": nodegroupRoleName,
        "LaunchTemplateName": launchTemplateName,
        "VpcId": vpcId,
        "SubnetIds": subnetIds,
        "NodeCount": eksNodeCount,
        "MDEOnNodes?": installMdeOnNodes,
        "AdditionalPorts": additionalPorts,
        "InstallFalco?": falcoBool,
        "FalcoDestinationType": falcoDestType,
        "FalcoDestination": falcoDest,
        "AmiOperatingSystem": amiOs,
        "AmiArhcitecture": amiArchitecture,
        "DatadogApiKey": datadogApiKey,
        "InstallDatadog?": datadogBool,
        "AdditionalAuthorizedPrincipals": additionalAuthZPrincipals,
    }

    print(f"The following attributes are set for your EKS Cluster")
    print(json.dumps(specDict, indent=4))
    # TODO: Save state?
    del specDict

    # Call the `builder` function
    ClusterManager.builder(
        kubernetes_version=k8sVersion,
        bucket_name=bucketName,
        ebs_volume_size=ebsVolumeSize,
        ami_id=amiId,
        instance_type=instanceType,
        cluster_name=clusterName,
        cluster_role_name=clusterRoleName,
        nodegroup_name=nodegroupName,
        nodegroup_role_name=nodegroupRoleName,
        launch_template_name=launchTemplateName,
        vpc_id=vpcId,
        subnet_ids=subnetIds,
        node_count=eksNodeCount,
        mde_on_nodes=installMdeOnNodes,
        additional_ports=additionalPorts,
        falco_bool=falcoBool,
        falco_sidekick_destination_type=falcoDestType,
        falco_sidekick_destination=falcoDest,
        ami_os=amiOs,
        ami_architecture=amiArchitecture,
        datadog_api_key=datadogApiKey,
        datadog_bool=datadogBool,
        addtl_auth_principals=additionalAuthZPrincipals,
    )

    stay_dangerous()


def delete_preflight_check():
    print_logo()

    # Call the `scheduled_deletion` function in the RollbackManager class
    RollbackManager.scheduled_deletion(
        cluster_name=clusterName,
        cluster_role_name=clusterRoleName,
        nodegroup_name=nodegroupName,
        nodegroup_role_name=nodegroupRoleName,
        launch_template_name=launchTemplateName,
    )

    stay_dangerous()


def update_preflight_check():
    print_logo()

    # Call the `update_kubernetes_version` function and attempt to version bump K8s of Clusters & Nodes
    UpdateManager.update_kubernetes_version(
        cluster_name=clusterName, kubernetes_version=k8sVersion, nodegroup_name=nodegroupName
    )

    stay_dangerous()


def assessment_preflight_check():
    """
    This function conducts a "preflight check" to ensure that required arguments are provided for the specified "Mode" before
    attempting to execute them.
    """
    print_logo()

    eks = boto3.client("eks")
    # Check if an EKS Cluster exists for provided name
    try:
        eks.describe_cluster(name=clusterName)
    except botocore.exceptions.ClientError as error:
        # If we have an "ResourceNotFoundException" error it means the cluster doesnt exist - which is what we want
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            print(
                f"An EKS Cluster with the name {clusterName} does not exist. Please specify another name and try again"
            )
            sys.exit(2)
        else:
            pass

    print(f"Downloading latest Kube-bench EKS config YAML")

    url = "https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml"
    wgetCommand = f"wget {url}"
    subProc = subprocess.run(wgetCommand, shell=True, capture_output=True)
    print(subProc.stderr.decode("utf-8"))

    print(f"Installing Trivy from source script for v0.24")
    # TODO: Continual updates of Trivy version https://aquasecurity.github.io/trivy
    trivyCmd = "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.24.0"
    trivyProc = subprocess.run(trivyCmd, shell=True, capture_output=True)
    print(trivyProc.stdout.decode("utf-8"))

    SecurityAssessment.start_assessment(cluster_name=clusterName)

    stay_dangerous()


def setup_falco_preflight_check():
    """
    This function conducts a "preflight check" to ensure that required arguments are provided for the specified "Mode" before
    attempting to execute them.
    """

    print_logo()

    eks = boto3.client("eks")
    # Check if an EKS Cluster exists for provided name
    try:
        eks.describe_cluster(name=clusterName)
    except botocore.exceptions.ClientError as error:
        # If we have an "ResourceNotFoundException" error it means the cluster doesnt exist - which is what we want
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            print(
                f"An EKS Cluster with the name {clusterName} does not exist. Please specify another name and try again"
            )
            sys.exit(2)
        else:
            pass

    if mode == "SetupFalco":
        if falcoDestType == "Slack" or falcoDestType == "Teams":
            if falcoDest == None:
                print(
                    f'No destination was provided for "--falco_sidekick_destination_type", please try again.'
                )
                sys.exit(2)
        elif falcoDestType == "Datadog":
            if datadogApiKey == None:
                print(
                    f"Datadog destination for Falco was specified but a Datadog API was not provided. Please provide a valid API key and try again."
                )
                sys.exit(2)

        FalcoSetup.falco_initialization(
            cluster_name=clusterName,
            falco_mode="Create",
            falco_sidekick_destination_type=falcoDestType,
            falco_sidekick_destination=falcoDest,
        )
        stay_dangerous()
    elif mode == "RemoveFalco":
        FalcoSetup.falco_initialization(
            cluster_name=clusterName,
            falco_mode="Delete",
            falco_sidekick_destination_type=falcoDestType,
            falco_sidekick_destination=falcoDest,
            datadog_api_key=datadogApiKey,
        )
        stay_dangerous()
    else:
        print(f"Somehow, an incompatible mode detected for Falco, please try again.")
        sys.exit(2)


def setup_datadog_preflight_check():
    """
    This function conducts a "preflight check" to ensure that required arguments are provided for the specified "Mode" before
    attempting to execute them.
    """
    print_logo()

    eks = boto3.client("eks")
    # Check if an EKS Cluster exists for provided name
    try:
        eks.describe_cluster(name=clusterName)
    except botocore.exceptions.ClientError as error:
        # If we have an "ResourceNotFoundException" error it means the cluster doesnt exist - which is what we want
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            print(
                f"An EKS Cluster with the name {clusterName} does not exist. Please specify another name and try again"
            )
            sys.exit(2)
        else:
            pass

    if mode == "SetupDatadog":
        if datadogApiKey == None:
            print(
                f"Datadog setup was specified but a Datadog API was not provided. Please provide a valid API key and try again."
            )
            sys.exit(2)
        # Datadoggy time!
        DatadogSetup.initialization(
            cluster_name=clusterName, datadog_mode="Setup", datadog_api_key=datadogApiKey
        )
    elif mode == "RemoveDatadog":
        # Bye Datadoggy time!
        DatadogSetup.initialization(
            cluster_name=clusterName, datadog_mode="Remove", datadog_api_key=datadogApiKey
        )
    else:
        print(f"Somehow, an incompatible mode detected for Datadog, please try again.")
        sys.exit(2)

    stay_dangerous()


if __name__ == "__main__":
    # Feed all of the arguments
    """
    >> argparse argument | **kwargs <<
    --profile | profile
    --mode | mode
    --k8s_version | kubernetes_version
    --s3_bucket_name | bucket_name
    --ebs_volume_size | ebs_volume_size
    --ami | ami_id
    --instance_type | instance_type
    --cluster_name | cluster_name
    --cluster_role_name | cluster_role_name
    --nodegroup_name | nodegroup_name
    --nodegroup_role_name | nodegroup_role_name
    --launch_template_name | launch_template_name
    --vpcid | vpc_id
    --subnets | subnet_ids
    --node_count | node_count
    --mde_on_nodes | mde_on_nodes
    --additional_ports | additional_ports
    --falco | falco_bool
    --falco_sidekick_destination_type | falco_sidekick_destination_type
    --falco_sidekick_destination | falco_sidekick_destination
    --ami_os | ami_os
    --ami_architecture | ami_architecture
    --datadog | datadog_bool
    --datadog_api_key | datadog_api_key
    --addtl_auth_principals | addtl_auth_principals
    """
    parser = argparse.ArgumentParser()

    # --profile
    parser.add_argument(
        "--profile",
        help="Specify Profile name if multiple profiles are used",
        required=False,
        default=[],
    )
    # --mode
    parser.add_argument(
        "--mode",
        help="Create, Destory or Update an existing Cluster. Updates limited to K8s Version bump. Destroy attempts to delete everything that this utility creates. Assessment will attempt to run various K8s security tools. SetupFalco will attempt to install Falco on existing Clusters. RemoveFalco will attempt to rollback SetupFalco deployments. SetupDatadog will attempt to install DataDog on existing Cluster. RemoveDatadog will attempt to rollback SetupDatadog deployments - defaults to Create",
        required=False,
        choices=[
            "Create",
            "Destroy",
            "Update",
            "Assessment",
            "SetupFalco",
            "RemoveFalco",
            "SetupDatadog",
            "RemoveDatadog",
        ],
        default="Create",
    )
    # --k8s_version
    parser.add_argument(
        "--k8s_version",
        help="Version of K8s to use for EKS - defaults to 1.21 as of 13 JAN 2022 - used for Create and Update",
        required=False,
        default="1.21",
    )
    # --s3_bucket_name
    parser.add_argument(
        "--s3_bucket_name",
        help="S3 Bucket with required artifacts for EKS to access for bootstrapping if --mde_on_nodes=True - used for Create",
        required=False,
        default=None,
    )
    # --ebs_volume_size
    parser.add_argument(
        "--ebs_volume_size",
        help="EBS volume size (in GB) for EKS nodegroup EC2 launch template - used for Create",
        required=False,
        default="20",
    )
    # --ami
    parser.add_argument(
        "--ami_id",
        help='Custom AMI ID for EKS nodegroup EC2 launch template. Defaults to "SSM" which tells the program to use an SSM-derived image for your K8s version matching --ami_os and --ami_architecture - used for Create',
        required=False,
        default="SSM",
    )
    # --instance_type
    parser.add_argument(
        "--instance_type",
        help="EC2 Instance type for EKS nodegroup EC2 launch template",
        required=False,
        default="t3.medium",
    )
    # --cluster_name
    parser.add_argument(
        "--cluster_name",
        help="Name for your EKS Cluster - used for Create, Delete and Update",
        required=False,
        default="LightspinECECluster",
    )
    # --cluster_role_name
    parser.add_argument(
        "--cluster_role_name",
        help="Name for your EKS Cluster Service IAM Role",
        required=False,
        default="ClusterServiceRoleForEKS",
    )
    # --nodegroup_name
    parser.add_argument(
        "--nodegroup_name",
        help="Name for your EKS Nodegroup - used for Create, Delete and Update",
        required=False,
        default="LightspinECENodegroup",
    )
    # --nodegroup_role_name
    parser.add_argument(
        "--nodegroup_role_name",
        help="Name for your EKS Nodegroup Service IAM Role (also given to policy)",
        required=False,
        default="NodegroupServiceRoleForEKS",
    )
    # --launch_template_name
    parser.add_argument(
        "--launch_template_name",
        help="Name for your Nodegroup EC2 launch template - used for Create and Delete",
        required=False,
        default="LightspinECECustomEKSAMI",
    )
    # --vpcid
    parser.add_argument(
        "--vpcid",
        help="VPC ID to launch EKS Cluster and Nodegroups into",
        required=False,
        default=None,
    )
    # --subnets
    # for help https://www.kite.com/python/answers/how-to-pass-a-list-as-an-argument-using-argparse-in-python
    parser.add_argument(
        "--subnets",
        nargs="+",
        help="Subnets to launch EKS Cluster and Nodegroups into - provide subnet IDs separated by spaces only",
        required=False,
    )
    # --node_count
    parser.add_argument(
        "--node_count",
        help="Amount of Nodes (EC2 instances) in EKS Nodegroup, will be used for min and desired values with 2 times for max - default 2",
        required=False,
        default="2",
    )
    # --mde_on_nodes
    parser.add_argument(
        "--mde_on_nodes",
        help="Whether or not to install MDE on EKS Nodes via bootstrap - requires S3 Bucket and install scripts if true - defaults to False",
        required=False,
        choices=["True", "False"],
        default="False",
    )
    # --additional_ports
    # for help https://www.kite.com/python/answers/how-to-pass-a-list-as-an-argument-using-argparse-in-python
    parser.add_argument(
        "--additional_ports",
        nargs="+",
        help="Additional application ports which need to be allowed in EKS Security Groups - 443, 53, 8765, 2801, and 10250 already included",
        required=False,
    )
    # --falco
    parser.add_argument(
        "--falco",
        help="For CREATE Mode, this flag specifies if you want to install and configure Falco on your Clusters - defaults to False",
        required=False,
        choices=["True", "False"],
        default="False",
    )
    # --falco_sidekick_destination_type
    parser.add_argument(
        "--falco_sidekick_destination_type",
        help="The output location for Falco Sidekick to send Falco alerts to. Defaults to SNS which also creates a new Topic unless a Destination is provided",
        required=False,
        choices=["SNS", "Slack", "Teams", "Datadog"],
        default="SNS",
    )
    # --falco_sidekick_destination
    parser.add_argument(
        "--falco_sidekick_destination",
        help="The logical location matching the Sidekick Destination Type to forward Falco alerts. E.g., ARN, Webhook URL, Datadog URL, etc.",
        required=False,
        default=None,
    )
    # --ami_os
    parser.add_argument(
        "--ami_os",
        help='If using "SSM" for --ami use this argument to specify what OS you want to use (alas = Amazon Linux 2, ubuntu = Ubuntu 20.04) - defaults to ubuntu',
        required=False,
        choices=["alas", "ubuntu"],
        default="ubuntu",
    )
    # --ami_architecture
    parser.add_argument(
        "--ami_architecture",
        help='If using "SSM" for --ami use this argument to specify what architecture you want to use - defaults to amd64',
        required=False,
        choices=["amd64", "arm64"],
        default="amd64",
    )
    # --datadog
    parser.add_argument(
        "--datadog",
        help="For CREATE Mode, this flag specifies if you want to install and configure Datadog APM on your Clusters - defaults to False",
        required=False,
        choices=["True", "False"],
        default="False",
    )
    # --datadog_api_key
    parser.add_argument(
        "--datadog_api_key",
        help="Datadog API Key. This is used for setting up Datadog with Create and SetupDatadog Modes as well as Datadog integration for FalcoSidekick",
        required=False,
        default=None,
    )
    # addtl_auth_principals
    # for help https://www.kite.com/python/answers/how-to-pass-a-list-as-an-argument-using-argparse-in-python
    parser.add_argument(
        "--addtl_auth_principals",
        nargs="+",
        help="Additional IAM Role ARNs to authorized as system:masters",
        required=False,
    )

    args = parser.parse_args()
    # Set Boto3 Profile if set
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    # Parse all arguments to be passed to various functions
    mode = args.mode
    k8sVersion = args.k8s_version
    bucketName = args.s3_bucket_name
    ebsVolumeSize = args.ebs_volume_size
    instanceType = args.instance_type
    clusterName = args.cluster_name
    clusterRoleName = args.cluster_role_name
    nodegroupName = args.nodegroup_name
    nodegroupRoleName = args.nodegroup_role_name
    launchTemplateName = args.launch_template_name
    vpcId = args.vpcid
    subnetIds = args.subnets
    eksNodeCount = args.node_count
    installMdeOnNodes = args.mde_on_nodes
    additionalPorts = args.additional_ports
    falcoBool = args.falco
    falcoDestType = args.falco_sidekick_destination_type
    falcoDest = args.falco_sidekick_destination
    amiOs = args.ami_os
    amiArchitecture = args.ami_architecture
    datadogBool = args.datadog
    datadogApiKey = args.datadog_api_key
    additionalAuthZPrincipals = args.addtl_auth_principals

    # This calls the creation function to create all needed IAM policies, roles and EC2/EKS infrastructure
    # will check if some infrastructure exists first to avoid needless exit later
    if mode == "Create":
        create_preflight_check()
    elif mode == "Destroy":
        delete_preflight_check()
    elif mode == "Update":
        update_preflight_check()
    elif mode == "Assessment":
        assessment_preflight_check()
    elif mode == "SetupFalco":
        setup_falco_preflight_check()
    elif mode == "RemoveFalco":
        setup_falco_preflight_check()
    elif mode == "SetupDatadog":
        setup_datadog_preflight_check()
    elif mode == "RemoveDatadog":
        setup_datadog_preflight_check()
    else:
        print(f"Somehow you provided an unexpected arguement, exiting!")
        sys.exit(2)
