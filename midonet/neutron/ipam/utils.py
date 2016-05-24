# Copyright 2015 OpenStack LLC.
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

import netaddr


def check_subnet_ip(cidr, ip_address):
    """Validate that the IP address is on the subnet."""
    ip = netaddr.IPAddress(ip_address)
    net = netaddr.IPNetwork(cidr)
    # Check that the IP is valid on subnet. This cannot be the
    # network or the broadcast address (which exists only in IPv4)
    return (ip != net.network
            and (net.version == 6 or ip != net[-1])
            and net.netmask & ip == net.network)
