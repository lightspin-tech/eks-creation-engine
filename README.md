# Lightspin EKS Creation Engine

The Amazon Elastic Kubernetes Service (EKS) Creation Engine (ECE) is a Python command-line program created by the Lightspin Office of the CISO to facilitate the creation and enablement of secure EKS Clusters, optionally further assured with continual Kubernetes Security Posture Management (KSPM), Runtime Protection, and Application Performance Monitoring (APM) capabilities.

## What is this :eyes: :eyes: ?? 

As stated above, the ECE is a Python utility to create a fully functioning EKS Cluster, complete with Nodegroups which are built off of EC2 Launch Templates as it was meant for creating EKS Nodegroups with custom AMIs with custom bootstrapping.

At a high-level ECE...

- Supports the full lifecycle of EKS management: Creation, Deletion, Rollbacks, and Updates
- Bootstraps Nodegroups based on IMDSv2 and Custom AMIs (**Currently supports Amazon Linux 2 & Ubuntu 20.04LTS Arm64 & Amd64**)
- Authorize additional IAM Principals into your Cluster
- Will install and configure [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) (MDE), Sysdig's [Falco](https://github.com/falcosecurity/falco) & [FalcoSidekick](https://github.com/falcosecurity/falcosidekick), and/or [Datadog](https://docs.datadoghq.com/agent/kubernetes/?tab=helm) if desired.
- Perform Kubernetes Security Posture Management (KSPM) tasks using Aqua Security's [Trivy](https://github.com/aquasecurity/trivy) (vulnerability management) and [Kube-bench](https://github.com/aquasecurity/kube-bench) (EKS CIS Benchmarking) into a [SARIF](https://sarifweb.azurewebsites.net/) JSON Report

After creating a Cluster with ECE, you are free to use your own tools such as `eksctl` or Terraform to further extend!

## Why use this over IAC :raised_eyebrow: :raised_eyebrow: ??

tl;dr = ECE will create a secure cluster the first time, every time, and support the security of your clusters throughout their lifetime better than AWS' own defaults.

For those using the Console, APIs, CLI, or SDKs to create your Cluster - AWS does not provide the best experience nor secure defaults - but ECE does.

 Feature | Default-by-AWS | Default-by-ECE |
| :---:        |     :---:      |         :---: |
| Public API Endpoint | :white_check_mark: | :x: |
| API Server Logging | :x: | :white_check_mark: |
| Audit Logging | :x: | :white_check_mark: |
| Authenticator Logging | :x: | :white_check_mark: |
| Controller Manage Logging | :x: | :white_check_mark: |
| Scheduler Logging | :x: | :white_check_mark: |
| Secrets Envelope Encryption | :x: | :white_check_mark: |
| Node Volume Encryption | :x: | :white_check_mark: |
| Minimum Necessary Secuirty Group Permissions | :x: | :white_check_mark: |
| Minimum Necessary IAM Role Permissions | :x: | :white_check_mark: |
| KMS Key Generation | :x: | :white_check_mark: |
| IMDSv2 on Nodes | :x: | :white_check_mark: |
| [EDR](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) on Nodes | :x: | :white_check_mark: |
| Dynamic Custom AMI bootstrapping | :x: | :white_check_mark: |
| [Falco](https://github.com/falcosecurity/falco) Configuration by Default | :x: | :white_check_mark: |
| [FalcoSidekick](https://github.com/falcosecurity/falcosidekick) Configuration by Default | :x: | :white_check_mark: |
| [CIS Benchmarking](https://github.com/aquasecurity/kube-bench) | :x: | :white_check_mark: |
| Container Vulnerability Scanning | :white_check_mark: | :white_check_mark: |

**Note:** Yes, we realize we are being cheeky with a lot of comparisons and features that AWS shouldn't be expected to provide, it's still concerning that AWS does not conform to their own best practices for defaults.

For those using Infrastructure-as-Code (IAC) such as AWS CloudFormation and HashiCorp's Terraform are the preferred vehicles for defining infrastructure, they can be complicated to write and maintain when getting started with AWS EKS. They also native capabilities to reach into clusters and provide post-provisioning without the usage of custom resources (CFN), `locals` and external `providers` (TF). This utility provides similar behavior patterns (creating, update, rollback) and can be used to quickly tune parameters and change conditions which are static within IAC. Further, ECE is also a secure tool used for vulnerability management, runtime protection configuration, and posture management in addition to being an IAC tool - something CloudFormation and Terraform would need additional infrastructure templates and outside tools to achieve.

## How do I use this :thinking: :thinking: ??

[Read the Docs here](./docs/HOWTO.md)

## FAQ :relieved: :relieved: ??

[Read the FAQ here](./docs/HOWTO.md)

## How can I contribute :arrow_upper_right: :arrow_upper_right: ??

We are happy to take contributions from anywhere that will help expand this project. Some things that immediately come to mind...

- Saving configurations to YAML/JSON and read from them.
- Support installing more software onto EKS Nodes (e.g., CloudWatch Agent, Kinesis Data Agent, Wazuh, etc.)
- Functionality for adding Nodegroups to existing Clusters.
- Spot provider & Fargate Profile support for Nodegroups, and an option to not use Nodegroups
- Create more Plugins for various utilities (e.g., Calico, OPA, NGINX Ingress Controller, etc.)

## Contact Us :telephone_receiver: :telephone_receiver:

For more information, contact us at support@lightspin.io.

## License :eight_spoked_asterisk: :eight_spoked_asterisk:

This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-kube/blob/main/LICENSE).