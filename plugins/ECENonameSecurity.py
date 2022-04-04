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

import subprocess

'''
This Class manages deployment of Noname Security's Kubernetes Agent (DaemonSet) onto an EKS Cluster and rollbacks / manual deletions
'''
class NonameSecuritySetup():

    def initialization(cluster_name, noname_mode):
        '''
        This function controls initialization of the NonameSecuritySetup Class. It will control installs, deletions, and rollbacks
        '''

        if noname_mode == 'Setup':
            print(f'Setting up Noname on EKS Cluster {cluster_name}')
            NonameSecuritySetup.install_noname()
        else:
            print(f'Rolling back Noname from EKS Cluster {cluster_name}')
            NonameSecuritySetup.uninstall_noname()

    def install_noname(noname_api_key):
        '''
        This function adds and updates existing Noname Security K8s Agent DaemonSets
        '''

        print(f'Installing Noname Docker Image secret-credentials')
        docker_user= 'changethis'
        docker_password= 'changethis'
        docker_registry='nonamesec.jfrog.io/noname-docker-sensor-release-local/3.1.0/noname-sensor'
        namespace='default'
        installnnDocker = f'kubectl create secret docker-registry secret-credentials --docker-server=$docker_registry --docker-username=$docker_user --docker-password=$docker_password --namespace=$namespace'
        installnnSubprocess1 = subprocess.run(installnnDocker, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        installnnMsg = str(installnnSubprocess1.stdout.decode('utf-8'))
        print(installnnMsg)

        # Use subprocess to configure Noname per initiation arguments from main.py

        print(f'Installing Noname Sensor')
        installnnSensor = f'kubectl apply -f noname_security_sensor.yml'
        installnnSubprocess2 = subprocess.run(installnnSensor, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        installnnMsg = str(installnnSubprocess2.stdout.decode('utf-8'))
        print(installnnMsg)
        

    def uninstall_noname():
        '''
        This function removes existing Noname Security K8s Agent DaemonSets
        '''

        # Uninstall Noname from EKS, /opt/noname/uninstall.sh 
        nnRemoveCmd = 'helm uninstall noname'
        nnRemoveSubprocess = subprocess.run(nnRemoveCmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nnRemoveMsg = str(nnRemoveSubprocess.stdout.decode('utf-8'))
        print(nnRemoveMsg)
