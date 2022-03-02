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
import re
import subprocess
import time

import boto3

"""
This Class manages various security assessment functions - such as running and saving Kube-bench CIS benchmarking and Trivy container scanning
"""


class SecurityAssessment:
    def start_assessment(cluster_name):
        """
        This function serves as the 'brain' of the security assessment. It will modify the Kubeconfig and attempt to run the other assessments
        it will also consolidate all findings in a SARIF JSON format for consumption in downstream tools
        """
        print(f"Starting security assessments for EKS Cluster {cluster_name}")

        # Retrieve region for AWS CLI kubectl generation
        session = boto3.session.Session()
        awsRegion = session.region_name

        updateKubeconfigCmd = (
            f"aws eks update-kubeconfig --region {awsRegion} --name {cluster_name}"
        )
        updateKubeconfigProc = subprocess.run(updateKubeconfigCmd, shell=True, capture_output=True)
        print(updateKubeconfigProc.stdout.decode("utf-8"))

        trivySarif = SecurityAssessment.run_trivy()
        kubebenchSarif = SecurityAssessment.run_kube_bench(cluster_name)

        print(f"Security assessments completed, starting SARIF consolidation.")

        sarifBase = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [],
        }

        for runs in trivySarif:
            sarifBase["runs"].append(runs)

        for runs in kubebenchSarif:
            sarifBase["runs"].append(runs)

        with open("./ECE_SecurityAssessment.sarif", "w") as jsonfile:
            json.dump(sarifBase, jsonfile, indent=4, default=str)

        print(
            f'Assessments completed and SARIF document created successfully as "ECE_SecurityAssessment.sarif".'
        )

    def run_trivy():
        """
        This function will run Trivy container vuln scanning against all running Containers in your Cluster and generate a report
        """
        # Create empty lists to contain unique values for reporting
        uniqueContainers = []
        trivyFindings = []

        print(f"Running Trivy")

        # Retrieve a list of all running Containers and create a unique list of them to pass to Trivy for scanning
        print(f"Retrieving list of all running Containers from your EKS Cluster")

        command = 'kubectl get pods --all-namespaces -o json | jq --raw-output ".items[].spec.containers[].image"'
        sub = subprocess.run(command, shell=True, capture_output=True)
        # pull list of container URIs from kubectl
        strList = str(sub.stdout.decode("utf-8"))
        # split by newline, as that is how it is retruned
        splitter = strList.split("\n")
        # Read the newly created list (created by `.split()`) and write unique names to List, ignoring the stray whitespace
        for i in splitter:
            if i not in uniqueContainers:
                if i == "":
                    pass
                else:
                    uniqueContainers.append(i)

        totalUniques = str(len(uniqueContainers))
        if totalUniques == "1":
            print(f"Trivy will scan {totalUniques} unique container image")
        else:
            print(f"Trivy will scan {totalUniques} unique container images")
        # mem clean up
        del splitter
        del strList

        # loop the list of unique container URIs and write the vulns to a new list
        for c in uniqueContainers:
            # passing '--quiet' will ensure the setup text from Trivy scanning does not make it into the JSON and corrupt it
            trivyScanCmd = f"trivy --quiet image --format sarif {c}"
            trivyScanSubprocess = subprocess.run(trivyScanCmd, shell=True, capture_output=True)
            trivyStdout = str(trivyScanSubprocess.stdout.decode("utf-8"))
            # load JSON object from stdout
            jsonItem = json.loads(trivyStdout)
            # loop the list of vulns
            print(f"Finished scanning Image URI {c}")
            for v in jsonItem["runs"]:
                trivyFindings.append(v)
                del v
            del c

        print(f"Completed Trivy scans of all unique running Containers in your Cluster")

        return trivyFindings

    def run_kube_bench(cluster_name):
        """
        This function will run Kube-bench EKS CIS benchmark against your cluster and generate a report
        """

        print(f"Running Kube-bench")

        # Create an empty list to hold normalized JSON findings once Kube-bench is converted
        findings = []

        # The SARIF JSON schema requires a URI for the 'artifact' location - which will point to the Cluster Endpoint
        eks = boto3.client("eks")
        clusterEndpoint = eks.describe_cluster(name=cluster_name)["cluster"]["endpoint"]

        del eks

        # Schedule the Job onto your EKS Cluster
        command = "kubectl apply -f job-eks.yaml"
        runJobSubproc = subprocess.run(command, shell=True, capture_output=True)
        print(runJobSubproc.stdout.decode("utf-8"))
        time.sleep(1.5)

        # Wait for Job to complete - use a short timeout to force a message to be piped sooner
        # https://stackoverflow.com/questions/63632084/kubectl-wait-for-a-pod-to-complete
        jobWaitCmd = "kubectl wait --for=condition=complete job/kube-bench --timeout=2s"
        # Really bad Regex hack to exit the `while True` loop - fuzzy match the stdout message
        completionRegex = re.compile("job.batch/kube-bench condition met")
        while True:
            jobWaitSubproc = subprocess.run(jobWaitCmd, shell=True, capture_output=True)
            jobWaitMessage = str(jobWaitSubproc.stdout.decode("utf-8"))
            completionRegexCheck = completionRegex.search(jobWaitMessage)
            if completionRegexCheck:
                print(f"Kube-bench Job completed! {jobWaitMessage}")
                break
            else:
                time.sleep(2)
                continue

        # `getPodCmd` used Kubectl to get pod names in all namespaces (-A). cut -d/ -f2 command is to split by the '/' and get the name
        # grep is used to ensure the right pod name is pulled as it always ends with a random 5 character hex (ex. kube-bench-z6r4b)
        getPodCmd = "kubectl get pods -o name -A | cut -d/ -f2 | grep kube-bench"
        getPodSubproc = subprocess.run(getPodCmd, shell=True, capture_output=True)
        # decoding adds newline or blank spaces - attempt to trim them
        kubebenchPodName = (
            str(getPodSubproc.stdout.decode("utf-8")).replace("\n", "").replace(" ", "")
        )

        # Pull logs from Job - this is the actual results of the job
        getLogsCmd = f"kubectl logs {kubebenchPodName}"
        getLogsSubproc = subprocess.run(getLogsCmd, shell=True, capture_output=True)
        getLogsStdout = str(getLogsSubproc.stdout.decode("utf-8"))
        # Split the block of text from STDOUT by newline delimiters to create a new list
        splitter = getLogsStdout.split("\n")

        # Use regex to match the Kube-Bench findings, they always start with a '[' which contains info such as '[PASS]'. We then match anything with 2 periods
        # as Kube-bench outputs 'headers' such as 3 or 3.1 - we want results such as '[PASS] 3.1.3 Ensure that the kubelet configuration file has permissions set to 644 or more restrictive (Manual)'
        # this is a horrible way to do it....but it works
        kubeBenchResultRegex = re.compile(r"^\[.*\..*\..*")
        for line in splitter:
            kubeBenchRegexCheck = kubeBenchResultRegex.search(line)
            if kubeBenchRegexCheck:
                # Once we find a match, split at the closing bracket and perform small transformations
                splitFinding = line.split("] ")
                # Handle the pass/fail/warn labels
                if splitFinding[0] == "[PASS":
                    findingStatus = "Passed"
                elif splitFinding[0] == "[WARN":
                    findingStatus = "Warning"
                else:
                    findingStatus = "Failed"
                # Create a new dict of the findings that will match a SARIF JSON 'run'
                # https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md
                run = {
                    "tool": {
                        "driver": {
                            "name": "Kube-bench",
                            "semanticVersion": "0.6.6",
                            "informationUri": "https://github.com/aquasecurity/kube-bench",
                            "organization": "Aqua Security",
                            "fullDescription": {
                                "text": "kube-bench is a tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark."
                            },
                        }
                    },
                    "results": [
                        {
                            "ruleId": splitFinding[1],
                            "message": {"text": findingStatus},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": clusterEndpoint,
                                            "description": {"text": cluster_name},
                                        }
                                    }
                                }
                            ],
                        }
                    ],
                    "columnKind": "utf16CodeUnits",
                }
                findings.append(run)
            else:
                continue

        del splitter

        # Delete the job from the EKS Cluster
        deleteKubebenchJobCmd = "kubectl delete -f job-eks.yaml"
        deleteKubebenchJobSubproc = subprocess.run(
            deleteKubebenchJobCmd, shell=True, capture_output=True
        )
        deleteKubebenchJobStdout = str(deleteKubebenchJobSubproc.stdout.decode("utf-8"))
        print(f"{deleteKubebenchJobStdout}")

        print(f"Completed Kube-bench assessment of EKS Cluster {cluster_name}")

        return findings
