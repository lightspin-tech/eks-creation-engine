# Lightspin EKS Creation Engine - How to Use

### Table of Contents

- [Installing Dependencies](#install-dependencies)
- [IAM Permissions](#ensure-you-have-the-necessary-iam-permissions)
- [Install Kubectl](#install-kubectl-example-shown-for-ubuntu-refer-here-for-other-os)
- [Install Helm](#install-helm-example-shown-for-ubuntu-refer-here-for-other-os)
- [Available Arguments](#list-all-arguments)
- [Creating a Cluster - Basic](#creating-a-cluster-with-the-minimum-required-arguements)
- [Creating a Cluster - Use AWS CLI Profile](#creating-a-cluster-with-the-minimum-required-arguements-using-another-aws-cli-profile)
- [Creating a Cluster - ARM64 Amazon Linux 2](#creating-a-cluster-with-the-minimum-required-arguements-using-amazon-linux-2-arm64-nodes)
- [Adding additional ports to EKS Security Groups](#creating-a-cluster-with-additional-ports-authorized-on-eks-security-groups)
- [Adding additional IAM Principals to EKS](#adding-additional-iam-principals-into-your-cluster)
- [Creating a Cluster with Falco](#creating-a-cluster-with-falco-pre-installed)
- [Creating a Cluster with Falco - custom destination](#creating-a-cluster-with-falco-pre-installed-that-sends-alerts-to-slack)
- [Creating a cluster with Microsoft Defender for Endpoint](#creating-a-cluster-with-microsoft-defender-for-endpoint-mde-installed-on-eks-nodes)
- [Deleting a Cluster](#destroying-a-cluster-created-by-eks-creation-engine-ece)
- [Updating K8s Version](#update-the-kubernetes-version-of-an-eks-cluster)
- [Conduct a Security Assessment against EKS](#conduct-a-security-assessment-against-an-eks-cluster)
- [Install Falco on existing Clusters](#install-and-configure-falco-on-an-existing-cluster)
- [Install Datadog on existing Clusters](#install-and-configure-datadog-on-an-existing-cluster)

### Install dependencies

```bash
git clone https://github.com/lightspin-tech/eks-creation-engine.git
cd eks-creation-engine
pip3 install -r requirements.txt
```

### Ensure you have the necessary IAM Permissions

[Review permissions here](./FAQ.md)

### Install `kubectl` (Example shown for Ubuntu, refer [here](https://kubernetes.io/docs/tasks/tools/#kubectl) for other OS')

```bash
sudo apt install -y apt-transport-https ca-certificates curl
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt update
sudo apt install -y kubectl
kubectl version
```

### Install `helm` (Example shown for Ubuntu, refer [here](https://helm.sh/docs/intro/install/) for other OS')

```bash
curl https://baltocdn.com/helm/signing.asc | sudo apt-key add -
sudo apt install apt-transport-https -y
echo "deb https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt update
sudo apt install helm -y
helm version
```

### List all arguments

```
python3 main.py -h
usage: main.py [-h] [--profile PROFILE]
               [--mode {Create,Destroy,Update,Assessment,SetupFalco,RemoveFalco,SetupDatadog,RemoveDatadog}]
               [--k8s_version K8S_VERSION] [--s3_bucket_name S3_BUCKET_NAME]
               [--ebs_volume_size EBS_VOLUME_SIZE] [--ami_id AMI_ID]
               [--instance_type INSTANCE_TYPE] [--cluster_name CLUSTER_NAME]
               [--cluster_role_name CLUSTER_ROLE_NAME]
               [--nodegroup_name NODEGROUP_NAME]
               [--nodegroup_role_name NODEGROUP_ROLE_NAME]
               [--launch_template_name LAUNCH_TEMPLATE_NAME] [--vpcid VPCID]
               [--subnets SUBNETS [SUBNETS ...]] [--node_count NODE_COUNT]
               [--mde_on_nodes {True,False}]
               [--additional_ports ADDITIONAL_PORTS [ADDITIONAL_PORTS ...]]
               [--falco {True,False}]
               [--falco_sidekick_destination_type {SNS,Slack,Teams,Datadog}]
               [--falco_sidekick_destination FALCO_SIDEKICK_DESTINATION]
               [--ami_os {alas,ubuntu}] [--ami_architecture {amd64,arm64}]
               [--datadog {True,False}] [--datadog_api_key DATADOG_API_KEY]
               [--addtl_auth_principals ADDTL_AUTH_PRINCIPALS [ADDTL_AUTH_PRINCIPALS ...]]

optional arguments:
  -h, --help            show this help message and exit
  --profile PROFILE     Specify Profile name if multiple profiles are used
  --mode {Create,Destroy,Update,Assessment,SetupFalco,RemoveFalco,SetupDatadog,RemoveDatadog}
                        Create, Destory or Update an existing Cluster. Updates
                        limited to K8s Version bump. Destroy attempts to
                        delete everything that this utility creates.
                        Assessment will attempt to run various K8s security
                        tools. SetupFalco will attempt to install Falco on
                        existing Clusters. RemoveFalco will attempt to
                        rollback SetupFalco deployments. SetupDatadog will
                        attempt to install DataDog on existing Cluster.
                        RemoveDatadog will attempt to rollback SetupDatadog
                        deployments - defaults to Create
  --k8s_version K8S_VERSION
                        Version of K8s to use for EKS - defaults to 1.21 as of
                        13 JAN 2022 - used for Create and Update
  --s3_bucket_name S3_BUCKET_NAME
                        S3 Bucket with required artifacts for EKS to access
                        for bootstrapping if --mde_on_nodes=True - used for
                        Create
  --ebs_volume_size EBS_VOLUME_SIZE
                        EBS volume size (in GB) for EKS nodegroup EC2 launch
                        template - used for Create
  --ami_id AMI_ID       Custom AMI ID for EKS nodegroup EC2 launch template.
                        Defaults to "SSM" which tells the program to use an
                        SSM-derived image for your K8s version matching
                        --ami_os and --ami_architecture - used for Create
  --instance_type INSTANCE_TYPE
                        EC2 Instance type for EKS nodegroup EC2 launch
                        template
  --cluster_name CLUSTER_NAME
                        Name for your EKS Cluster - used for Create, Delete
                        and Update
  --cluster_role_name CLUSTER_ROLE_NAME
                        Name for your EKS Cluster Service IAM Role
  --nodegroup_name NODEGROUP_NAME
                        Name for your EKS Nodegroup - used for Create, Delete
                        and Update
  --nodegroup_role_name NODEGROUP_ROLE_NAME
                        Name for your EKS Nodegroup Service IAM Role (also
                        given to policy)
  --launch_template_name LAUNCH_TEMPLATE_NAME
                        Name for your Nodegroup EC2 launch template - used for
                        Create and Delete
  --vpcid VPCID         VPC ID to launch EKS Cluster and Nodegroups into
  --subnets SUBNETS [SUBNETS ...]
                        Subnets to launch EKS Cluster and Nodegroups into -
                        provide subnet IDs separated by spaces only
  --node_count NODE_COUNT
                        Amount of Nodes (EC2 instances) in EKS Nodegroup, will
                        be used for min and desired values with 2 times for
                        max - default 2
  --mde_on_nodes {True,False}
                        Whether or not to install MDE on EKS Nodes via
                        bootstrap - requires S3 Bucket and install scripts if
                        true - defaults to False
  --additional_ports ADDITIONAL_PORTS [ADDITIONAL_PORTS ...]
                        Additional application ports which need to be allowed
                        in EKS Security Groups - 443, 53, 8765, 2801, and
                        10250 already included
  --falco {True,False}  For CREATE Mode, this flag specifies if you want to
                        install and configure Falco on your Clusters -
                        defaults to False
  --falco_sidekick_destination_type {SNS,Slack,Teams,Datadog}
                        The output location for Falco Sidekick to send Falco
                        alerts to. Defaults to SNS which also creates a new
                        Topic unless a Destination is provided
  --falco_sidekick_destination FALCO_SIDEKICK_DESTINATION
                        The logical location matching the Sidekick Destination
                        Type to forward Falco alerts. E.g., ARN, Webhook URL,
                        Datadog URL, etc.
  --ami_os {alas,ubuntu}
                        If using "SSM" for --ami use this argument to specify
                        what OS you want to use (alas = Amazon Linux 2, ubuntu
                        = Ubuntu 20.04) - defaults to ubuntu
  --ami_architecture {amd64,arm64}
                        If using "SSM" for --ami use this argument to specify
                        what architecture you want to use - defaults to amd64
  --datadog {True,False}
                        For CREATE Mode, this flag specifies if you want to
                        install and configure Datadog APM on your Clusters -
                        defaults to False
  --datadog_api_key DATADOG_API_KEY
                        Datadog API Key. This is used for setting up Datadog
                        with Create and SetupDatadog Modes as well as Datadog
                        integration for FalcoSidekick
  --addtl_auth_principals ADDTL_AUTH_PRINCIPALS [ADDTL_AUTH_PRINCIPALS ...]
                        Additional IAM Principal ARNs to authorized as
                        system:masters
```

### Creating a Cluster with the minimum required arguements

```bash
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123
```

### Creating a Cluster with the minimum required arguements, using another AWS CLI Profile

```bash
python3 main.py \
    --profile dev \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123
```

### Creating a Cluster with the minimum required arguements, using Amazon Linux 2 ARM64 Nodes

```bash
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123 \
    --ami_os alas \
    --ami_architecture arm64
```

### Creating a Cluster with additional ports authorized on EKS Security Groups

```bash
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123 \
    --additional_ports 80 1541 8001
```

### Adding additional IAM Principals into your Cluster

```bash
sudo apt install -y jq
AWS_ACCOUNT=$(aws sts get-caller-identity | jq -r '.Account')
ROLE_NAME_ONE='<some_role_name>'
ROLE_NAME_TWO='<some_role_name>'
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123
    --addtl_auth_principals arn:aws:iam::$AWS_ACCOUNT:role/$ROLE_NAME_ONE arn:aws:iam::$AWS_ACCOUNT:role/$ROLE_NAME_TWO
```

### Creating a Cluster with Falco pre-installed

```bash
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123 \
    --falco True
```

**Note:** The default allowed ports created by ECE are: TCP 443, TCP 10250, TCP & UDP 53 as reccomended by AWS and TCP 2801 and TCP 8765 for Falco and FalcoSidekick, respectively.

**Another Note:** This configuration will create a SNS Topic for Falco to send your alerts to via FalcoSidekick

### Creating a cluster with Falco pre-installed that sends Alerts to Slack

```bash
SLACK_WEBHOOK="https://hooks.slack.com/services/XXXX"
python3 main.py \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123 \
    --falco True \
    --falco_sidekick_destination_type Slack \
    --falco_sidekick_destination $SLACK_WEBHOOK
```

### Creating a Cluster with Microsoft Defender for Endpoint (MDE) installed on EKS Nodes

- First, navigate to [Endpoints Onboarding](https://security.microsoft.com/preferences2/onboarding) in the MDE Console.

- Second, download a Linux onboarding script from the page by choosing **Linux Server** from the OS dropdown menu, ensure you choose **Local Script** for your Deployment method and select **Download onboarding package**

- Finally, upload the script (which is a `.zip` file) to a S3 bucket of your choosing within a path named `/mdatp` as shown below.

```bash
S3_BUCKET='BUCKET_NAME'
aws s3 cp ./WindowsDefenderATPOnboardingPackage.zip s3://$S3_BUCKET/mdatp/WindowsDefenderATPOnboardingPackage.zip
```

- Ensure you provide the name of your bucket in the arg `--s3_bucket_name` as shown below, ECE will do the rest.

```bash
python3 main.py \
    --s3_bucket_name $S3_BUCKET \
    --mde_on_nodes True \
    --subnets subnet-123 subnet-456 \
    --vpcid vpc-123
```

### Destroying a cluster created by EKS Creation Engine (ECE)

```bash
python3 main.py \
    --mode Destroy \
    --cluster_name $CLUSTER_NAME \
    --cluster_role_name $CLUSTER_ROLE_NAME \
    --nodegroup_name $NODEGROUP_NAME \
    --nodegroup_role_name $NODEGROUP_ROLE_NAME \
    --launch_template_name $LAUNCH_TEMPLATE_NAME
```

### Update the Kubernetes version of an EKS cluster

**Note:** You can install Falco on ***any*** EKS Cluster, created by ECE or otherwise, using the `kubectl config use-context <CONTEXT-NAME>` command

```bash
python3 main.py \
    --mode Update \
    --cluster_name $CLUSTER_NAME \
    --nodegroup_name $NODEGROUP_NAME \
    --kubernetes_version $K8S_VERSION
```

### Conduct a security assessment against an EKS cluster

**Note:** You can run the Security Assessment against ***any*** EKS Cluster, created by ECE or otherwise, using the `kubectl config use-context <CONTEXT-NAME>` command

```bash
python3 main.py \
    --mode Assessment \
    --cluster_name $CLUSTER_NAME
```

### Install and configure Falco on an existing cluster

**Note:** You can install Falco on ***any*** EKS Cluster, created by ECE or otherwise, using the `kubectl config use-context <CONTEXT-NAME>` command

```bash
SLACK_WEBHOOK="https://hooks.slack.com/services/XXXX"
python3 main.py \
    --mode SetupFalco \
    --falco_sidekick_destination_type Slack \
    --falco_sidekick_destination $SLACK_WEBHOOK \
    --cluster_name $CLUSTER_NAME
```

### Install and configure Datadog on an existing cluster

**Note:** You can install Datadog on ***any*** EKS Cluster, created by ECE or otherwise, using the `kubectl config use-context <CONTEXT-NAME>` command

- Create (or locate) your Datadog API Key and place it in a secure location such as AWS Systems Manager (SSM) Parameter Store or Hashicorp Vault (*example shown for AWS SSM*)

```bash
DATADOG_PARAM_NAME='DatadogAPIKey'
aws ssm put-parameter --name $DATADOG_PARAM_NAME --description 'Datadog onboarding API Key' --type SecureString --value <YOUR_KEY_HERE>
```

- Retrieve your Datadog API key from the secure location (*example shown for AWS SSM*)

```bash
DATADOG_API_KEY=$(aws ssm get-parameter --name $DATADOG_PARAM_NAME --with-decryption | jq --raw-output '.Parameter.Value')
echo $DATADOG_API_KEY
```

- Use the EKS Creation Engine (ECE) CLI

```bash
python3 main.py \
    --mode SetupDatadog \
    --datadog_api_key $DATADOG_API_KEY \
    --cluster_name $CLUSTER_NAME
```

## Contact Us :telephone_receiver: :telephone_receiver:

For more information, contact us at support@lightspin.io.

## License :eight_spoked_asterisk: :eight_spoked_asterisk:

This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/eks-creation-engine/blob/main/LICENSE).