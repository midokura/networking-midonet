# Copyright (C) 2015 Midokura SARL.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Network Type constants
TYPE_UPLINK = 'uplink'

# Neutron well-known service type constants:
GATEWAY_DEVICE = "GATEWAY_DEVICE"

MAX_VXLAN_VNI = 16777215

# for resource name on callback method
MIDONET_NETWORK = "midonet_network"

# for event name on callback method
# "before_" is a key word to raise exception in neutron.callbacks.manager.
PRECOMMIT_DELETE = "before_delete"
