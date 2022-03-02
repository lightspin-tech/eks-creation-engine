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
import subprocess

'''
This Class manages deployment of Datadog onto an EKS Cluster and rollbacks / manual deletions
'''


class DatadogSetup:
    def initialization(cluster_name, datadog_mode, datadog_api_key):
        '''
        This function controls initialization of the DatadogSetup Class. It will control installs, deletions, and rollbacks
        '''

        if datadog_mode == 'Setup':
            print(f'Setting up Datadog on EKS Cluster {cluster_name}')
            DatadogSetup.install_datadog(datadog_api_key)
        else:
            print(f'Rolling back Datadog from EKS Cluster {cluster_name}')
            DatadogSetup.uninstall_datadog()

    def install_datadog(datadog_api_key):
        '''
        This function adds and updates existing Datadog Charts and applies the Chart to your EKS Cluster
        '''

        # Use subprocess to add Datadog Charts using Helm
        print(f'Adding Datadog Helm Charts')
        datadogHelmChartAddCmd = (
            'helm repo add datadog https://helm.datadoghq.com && helm repo update'
        )
        datadogHelmChartAddSubprocess = subprocess.run(
            datadogHelmChartAddCmd, shell=True, capture_output=True
        )
        datadogHelmChartAddMsg = str(datadogHelmChartAddSubprocess.stdout.decode('utf-8'))
        print(datadogHelmChartAddMsg)

        # Use subprocess to configure Datadog per initiation arguments from main.py
        print(f'Installing Datadog')
        installDatadogCmd = f'helm install datadog-agent --set targetSystem=linux --set datadog.apiKey={datadog_api_key} datadog/datadog'
        installDatadogSubprocess = subprocess.run(
            installDatadogCmd, shell=True, capture_output=True
        )
        installDatadogMsg = str(installDatadogSubprocess.stdout.decode('utf-8'))
        print(installDatadogMsg)

    def uninstall_datadog():
        '''
        This function uninstalls Datadog from your EKS Cluster
        '''

        # Uninstall Datadog from EKS
        datadogRemoveCmd = 'helm uninstall datadog-agent'
        datadogRemoveSubprocess = subprocess.run(datadogRemoveCmd, shell=True, capture_output=True)
        datadogRemoveMsg = str(datadogRemoveSubprocess.stdout.decode('utf-8'))
        print(datadogRemoveMsg)
