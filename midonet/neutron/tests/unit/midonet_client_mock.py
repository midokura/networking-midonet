# Copyright (C) 2016 Midokura SARL.
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

from midonet.neutron.client import base as cli_base

from neutron import i18n

from oslo_log import log as logging

LOG = logging.getLogger(__name__)
_LE = i18n._LE
_LW = i18n._LW


class LocalCache(object):
    def __init__(self):
        self.security_group = {}
        self.security_group_rule = {}
        self.security_group_ip = {}
        self.all_ipaddrs = {}

    def create_sg(self, sg):
        self.security_group[sg['id']] = sg
        self.security_group_rule[sg['id']] = sg.get('security_group_rules', [])
        self.security_group_ip[sg['id']] = sg.get('ips', [])
        self.all_ipaddrs[sg['id']] = []
        return sg

    def delete_sg(self, id):
        self.security_group.pop(id)
        self.security_group_rule.pop(id)
        self.security_group_ip.pop(id)
        self.all_ipaddrs.pop(id)
        return

    def create_sg_rule(self, sg_rule):
        sgid = sg_rule.get('security_group_id')
        rules = self.security_group_rule[sgid]
        rules.append(sg_rule)
        self.security_group_rule[sgid] = rules
        self.security_group[sgid]['security_group_rules'] = rules
        return sg_rule

    def delete_sg_rule(self, sg_rule_id):
        for k, v in self.security_group_rule.iteritems():
            if v:
                remove_index = None
                for i in range(len(v)):
                    if v[i].get('id') == sg_rule_id:
                        remove_index = i
                if remove_index:
                    v.remove(v[remove_index])
                    self.security_group_rule[k] = v
                    self.security_group[k]['security_group_rules'] = v
        return

    def get_sgs(self):
        res = []
        for v in self.security_group.values():
            res.append(v)
        return res

    def create_ipaddr(self, ipg_addr):
        sgid = ipg_addr['ipAddrGroupId']
        ip_addr = {'version': ipg_addr['version'],
                   'uri': 'dummy-' + sgid,
                   'addr': ipg_addr['addr'],
                   'ipAddrGroup': sgid
                   }
        if sgid in self.all_ipaddrs.keys():
            self.all_ipaddrs[sgid].append(ip_addr)
        else:
            raise Exception("Not found ipAddrGroup")
        return ip_addr

    def delete_ipaddr(self, ipg_id, v, addr):
        if not (ipg_id in self.all_ipaddrs.keys()):
            return
        ipaddrs = self.all_ipaddrs[ipg_id]
        remove_index = None
        for i in range(len(ipaddrs)):
            if ipaddrs[i]['addr'] == addr:
                remove_index = i
        if remove_index:
            self.all_ipaddrs[ipg_id].pop(remove_index)
        return

    def get_ipaddr(self, security_group_id):
        return self.all_ipaddrs[security_group_id]


class LocalMidonetClient(cli_base.MidonetClientBase):
    """Dummy midonet client used for the unit tests of regional sg"""

    def __init__(self):
        self.local_db = LocalCache()

    def create_security_group_postcommit(self, security_group):
        LOG.info(_("Midonet: create_security_group req: %s"), security_group)
        res = self.local_db.create_sg(security_group)
        LOG.info(_("Midonet: create_security_group res: %s"), res)
        return res

    def delete_security_group_postcommit(self, sg_id):
        LOG.info(_("Midonet: delete_security_group req: %s"), sg_id)
        res = self.local_db.delete_sg(sg_id)
        return res

    def create_security_group_rule_postcommit(self, sg_rule):
        LOG.info(_("Midonet: create_security_group_rule req: %s"), sg_rule)
        res = self.local_db.create_sg_rule(sg_rule)
        LOG.info(_("Midonet: create_security_group_rule res: %s"), res)
        return res

    def delete_security_group_rule_postcommit(self, sg_rule_id):
        LOG.info(_("Midonet: delete_security_group_rule req: %s"), sg_rule_id)
        res = self.local_db.delete_sg_rule(sg_rule_id)
        return res

    def get_security_groups(self):
        res = self.local_db.get_sgs()
        LOG.info(_("Midonet: get_security_groups res: %s"), res)
        return res

    def update_security_group(self, security_group_id, security_group):
        pass

    def get_ipaddr_group_addrs(self, security_group_id):
        res = self.local_db.get_ipaddr(security_group_id)
        LOG.info(_("Midonet: get_ipaddr_group_addrs res: %s"), res)
        return res

    def create_ipaddr_group_addr(self, ipg_addr):
        LOG.info(_("Midonet: create_ipaddr_group_addr req: %s"), ipg_addr)
        res = self.local_db.create_ipaddr(ipg_addr)
        LOG.info(_("Midonet: create_ipaddr_group_addr res: %s"), res)
        return res

    def delete_ipaddr_group_addr(self, ipg_id, v, addr):
        LOG.info(_("Midonet: delete_ipaddr_group_addr req: sgid: "
                   "%(sgid)s, ip: %(ip)s"), {'sgid': ipg_id, 'ip': addr})
        res = self.local_db.delete_ipaddr(ipg_id, v, addr)
        return res

    def update_ipaddr_group(self, security_group_id, ips):
        # TODO(fj and midokura): decide method name
        pass
