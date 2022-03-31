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

    def initialization(cluster_name, noname_mode, noname_api_key):
        '''
        This function controls initialization of the NonameSecuritySetup Class. It will control installs, deletions, and rollbacks
        '''

        if noname_mode == 'Setup':
            print(f'Setting up Noname on EKS Cluster {cluster_name}')
            NonameSecuritySetup.install_noname(noname_api_key)
        else:
            print(f'Rolling back Noname from EKS Cluster {cluster_name}')
            NonameSecuritySetup.uninstall_noname()

    def install_noname(noname_api_key):
        '''
        This function adds and updates existing Noname Security K8s Agent DaemonSets
        '''

        return None

    def uninstall_noname():
        '''
        This function removes existing Noname Security K8s Agent DaemonSets
        '''

        return None