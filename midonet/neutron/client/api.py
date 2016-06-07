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

from midonet.neutron.client import base

from midonetclient import client
from midonetclient import url_provider
from midonetclient import util
from midonetclient import vendor_media_type as mt


class IpAddrGroupUrlProviderMixin(url_provider.UrlProviderMixin):
    """Ip Addr Group URL provider mixin

    This mixin provides URLs for ip addr group rules.
    """

    def ipaddr_group_url(self, ipg_id):
        return self.template_url("ipAddrGroupTemplate", ipg_id)

    def ipaddr_groups_url(self):
        return self.resource_url("ipAddrGroups")

    def ipaddr_group_addr_url(self, ipg_id, addr):
        return self.ipaddr_group_addrs_url(ipg_id) + "/" + addr

    def ipaddr_group_addrs_url(self, ipg_id):
        return self.ipaddr_group_url(ipg_id) + "/ip_addrs"

    def ipaddr_group_version_addr_url(self, ipg_id, v, addr):
        return self.ipaddr_group_version_url(ipg_id, v) + "/ip_addrs/" + addr

    def ipaddr_group_version_url(self, ipg_id, v):
        return self.ipaddr_group_url(ipg_id) + "/versions/" + v


class IpAddrGroupClientMixin(IpAddrGroupUrlProviderMixin):
    """Ip Addr Group mixin

    Mixin that defines all the Neutron ip addr group operations in MidoNet API.
    """

    @util.convert_case
    def create_ipaddr_group(self, ipg):
        return self.client.post(self.ipaddr_groups_url(),
                                mt.APPLICATION_IP_ADDR_GROUP_JSON, body=ipg)

    def delete_ipaddr_group(self, ipg_id):
        self.client.delete(self.ipaddr_group_url(ipg_id))

    @util.convert_case
    def get_ipaddr_group(self, ipg_id, fields=None):
        return self.client.get(self.ipaddr_group_url(ipg_id),
                               mt.APPLICATION_IP_ADDR_GROUP_JSON)

    @util.convert_case
    def get_ipaddr_groups(self, filters=None, fields=None, sorts=None,
                          limit=None, marker=None, page_reverse=False):
        return self.client.get(self.ipaddr_groups_url(),
                               mt.APPLICATION_IP_ADDR_GROUP_COLLECTION_JSON)

    @util.convert_case
    def update_ipaddr_group(self, ipg):
        return self.client.put(self.ipaddr_group_url(ipg["id"]),
                               mt.APPLICATION_IP_ADDR_GROUP_JSON, ipg)

    @util.convert_case
    def create_ipaddr_group_addr(self, ipg_addr):
        # convert_case converted to camel
        return self.client.post(
            self.ipaddr_group_addrs_url(ipg_addr["ipAddrGroupId"]),
            mt.APPLICATION_IP_ADDR_GROUP_ADDR_JSON, body=ipg_addr)

    def delete_ipaddr_group_addr(self, ipg_id, v, addr):
        self.client.delete(self.ipaddr_group_version_addr_url(ipg_id, v,
                                                              addr))

    @util.convert_case
    def get_ipaddr_group_addr(self, ipg_id, v, addr):
        return self.client.get(self.ipaddr_group_version_addr_url(ipg_id, v,
                                                                  addr),
                               mt.APPLICATION_IP_ADDR_GROUP_ADDR_JSON)

    @util.convert_case
    def get_ipaddr_group_addrs(self, ipg_id):
        return self.client.get(
            self.ipaddr_group_addrs_url(ipg_id),
            mt.APPLICATION_IP_ADDR_GROUP_ADDR_COLLECTION_JSON)


class MidonetFjClient(IpAddrGroupClientMixin,
                      client.MidonetClient):
    """Extend MidonetClient to implement FJ specific methods

    There are MidoNet API that must be made available only for FJ.  Implement
    the client code here so that the upstream client class remains unaware.
    """
    pass


class MidonetApiClient(base.MidonetClientBase):

    def __init__(self, conf):
        self.api_cli = MidonetFjClient(conf.midonet_uri, conf.username,
                                       conf.password,
                                       project_id=conf.project_id)

    def create_network_postcommit(self, network):
        self.api_cli.create_network(network)

    def update_network_postcommit(self, network_id, network):
        self.api_cli.update_network(network_id, network)

    def delete_network_postcommit(self, network_id):
        self.api_cli.delete_network(network_id)

    def create_subnet_postcommit(self, subnet):
        self.api_cli.create_subnet(subnet)

    def update_subnet_postcommit(self, subnet_id, subnet):
        self.api_cli.update_subnet(subnet_id, subnet)

    def delete_subnet_postcommit(self, subnet_id):
        self.api_cli.delete_subnet(subnet_id)

    def create_port_postcommit(self, port):
        self.api_cli.create_port(port)

    def update_port_postcommit(self, port_id, port):
        self.api_cli.update_port(port_id, port)

    def delete_port_postcommit(self, port_id):
        self.api_cli.delete_port(port_id)

    def create_router_postcommit(self, router):
        self.api_cli.create_router(router)

    def update_router_postcommit(self, router_id, router):
        self.api_cli.update_router(router_id, router)

    def delete_router_postcommit(self, router_id):
        self.api_cli.delete_router(router_id)

    def add_router_interface_postcommit(self, router_id, interface_info):
        self.api_cli.add_router_interface(router_id, interface_info)

    def remove_router_interface_postcommit(self, router_id, interface_info):
        self.api_cli.remove_router_interface(router_id, interface_info)

    def create_floatingip_postcommit(self, floatingip):
        self.api_cli.create_floating_ip(floatingip)

    def update_floatingip_postcommit(self, floatingip_id, floatingip):
        self.api_cli.update_floating_ip(floatingip_id, floatingip)

    def delete_floatingip_postcommit(self, floatingip_id):
        self.api_cli.delete_floating_ip(floatingip_id)

    def create_security_group_postcommit(self, security_group):
        self.api_cli.create_security_group(security_group)

    def delete_security_group_postcommit(self, security_group_id):
        self.api_cli.delete_security_group(security_group_id)

    def create_security_group_rule_postcommit(self, security_group_rule):
        self.api_cli.create_security_group_rule(security_group_rule)

    def create_security_group_rule_bulk_postcommit(self, security_group_rules):
        self.api_cli.create_security_group_rule_bulk(security_group_rules)

    def delete_security_group_rule_postcommit(self, security_group_rule_id):
        self.api_cli.delete_security_group_rule(security_group_rule_id)

    # Fj Regional Security group extension

    def get_security_groups(self):
        return self.api_cli.get_security_groups()

    def get_ipaddr_group_addrs(self, security_group_id):
        return self.api_cli.get_ipaddr_group_addrs(security_group_id)

    def create_ipaddr_group_addr(self, ipg_addr):
        return self.api_cli.create_ipaddr_group_addr(ipg_addr)

    def delete_ipaddr_group_addr(self, ipg_id, v, addr):
        return self.api_cli.delete_ipaddr_group_addr(ipg_id, v, addr)

    def create_vip(self, context, vip):
        self.api_cli.create_vip(vip)

    def update_vip(self, context, vip_id, vip):
        self.api_cli.update_vip(vip_id, vip)

    def delete_vip(self, context, vip_id):
        self.api_cli.delete_vip(vip_id)

    def create_pool(self, context, pool):
        self.api_cli.create_pool(pool)

    def update_pool(self, context, pool_id, pool):
        self.api_cli.update_pool(pool_id, pool)

    def delete_pool(self, context, pool_id):
        self.api_cli.delete_pool(pool_id)

    def create_member(self, context, member):
        self.api_cli.create_member(member)

    def update_member(self, context, member_id, member):
        self.api_cli.update_member(member_id, member)

    def delete_member(self, context, member_id):
        self.api_cli.delete_member(member_id)

    def create_health_monitor(self, context, health_monitor):
        self.api_cli.create_health_monitor(health_monitor)

    def update_health_monitor(self, context, health_monitor_id,
                              health_monitor):
        self.api_cli.update_health_monitor(health_monitor_id, health_monitor)

    def delete_health_monitor(self, context, health_monitor_id):
        self.api_cli.delete_health_monitor(health_monitor_id)

    def create_firewall(self, context, firewall):
        self.api_cli.create_firewall(firewall)

    def delete_firewall(self, context, firewall):
        self.api_cli.delete_firewall(firewall['id'])

    def update_firewall(self, context, firewall):
        self.api_cli.update_firewall(firewall['id'], firewall)

    def create_vpn_service(self, context, vpn_service):
        self.api_cli.create_vpn_service(vpn_service)

    def update_vpn_service(self, context, vpn_service_id, vpn_service):
        self.api_cli.update_vpn_service(vpn_service_id, vpn_service)

    def delete_vpn_service(self, context, vpn_service_id):
        self.api_cli.delete_vpn_service(vpn_service_id)

    def create_ipsec_site_conn(self, context, ipsec_site_conn):
        self.api_cli.create_ipsec_site_conn(ipsec_site_conn)

    def update_ipsec_site_conn(self, context, ipsec_site_conn_id,
            ipsec_site_conn):
        self.api_cli.update_ipsec_site_conn(ipsec_site_conn_id,
                ipsec_site_conn)

    def delete_ipsec_site_conn(self, context, ipsec_site_conn_id):
        self.api_cli.delete_ipsec_site_conn(ipsec_site_conn_id)

    def create_gateway_device_postcommit(self, gw_dev):
        self.api_cli.create_gateway_device(gw_dev)

    def update_gateway_device_postcommit(self, gw_dev_id, gw_dev):
        self.api_cli.update_gateway_device(gw_dev_id, gw_dev)

    def delete_gateway_device_postcommit(self, gw_dev_id):
        self.api_cli.delete_gateway_device(gw_dev_id)

    def create_gateway_device_remote_mac_entry_postcommit(self, mac_entry):
        self.api_cli.create_remote_mac_entry(mac_entry)

    def delete_gateway_device_remote_mac_entry_postcommit(self, mac_entry_id):
        self.api_cli.delete_remote_mac_entry(mac_entry_id)

    def create_l2_gateway_connection(self, context, l2_gw_conn):
        self.api_cli.create_l2gw_conn(l2_gw_conn)

    def delete_l2_gateway_connection(self, context, l2_gw_conn_id):
        self.api_cli.delete_l2gw_conn(l2_gw_conn_id)

    def update_bgp_speaker_postcommit(self, bgp_speaker_id, bgp_speaker):
        self.api_cli.update_bgp_speaker(bgp_speaker_id, bgp_speaker)

    def create_bgp_peer_postcommit(self, bgp_peer):
        self.api_cli.create_bgp_peer(bgp_peer)

    def update_bgp_peer_postcommit(self, bgp_peer_id, bgp_peer):
        self.api_cli.update_bgp_peer(bgp_peer_id, bgp_peer)

    def delete_bgp_peer_postcommit(self, bgp_peer_id):
        self.api_cli.delete_bgp_peer(bgp_peer_id)

    def update_logging_resource_postcommit(
                self, logging_resource_id, logging_resource):
        self.api_cli.update_logging_resource(
                logging_resource_id, logging_resource)

    def delete_logging_resource_postcommit(self, logging_resource_id):
        self.api_cli.delete_logging_resource(logging_resource_id)

    def create_firewall_log_postcommit(self, firewall_log):
        self.api_cli.create_firewall_log(firewall_log)

    def update_firewall_log_postcommit(self, firewall_log_id, firewall_log):
        self.api_cli.update_firewall_log(firewall_log_id, firewall_log)

    def delete_firewall_log_postcommit(self, firewall_log_id):
        self.api_cli.delete_firewall_log(firewall_log_id)
