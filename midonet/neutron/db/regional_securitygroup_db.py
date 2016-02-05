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
import webob.exc

from midonet.neutron.client import sg_client
from midonet.neutron.extensions import regional_securitygroup as regional_sg

from neutron.api.v2 import attributes as attr
from neutron.common import utils
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import securitygroup as ext_sg
from neutron import i18n

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils


LOG = logging.getLogger(__name__)
_LE = i18n._LE
_LW = i18n._LW


class RegionalSecurityGroupDbMixin(ext_sg.SecurityGroupPluginBase,
                                  regional_sg.RegionalSecurityGroupPluginBase):
    """Mixin class to add regional security group to MidoneRegionalSGPlugin.

    In Regional SecurityGroup, SecurityGroup data are maintained by SG service,
    so this class doesn't have SecurityGroup data in NeutronDB and
    accesses SG service via sg_client when needs SecurityGroup data.
    """

    __native_bulk_support = False

    def create_security_group(self, context, security_group):
        return sg_client.create_security_group(context, security_group)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None,
                            marker=None, page_reverse=False):
        res = sg_client.get_security_groups(context, filters=filters)
        if not fields:
            return res
        return [self._fields(sg, fields) for sg in res]

    def get_security_groups_count(self, context, filters=None):
        res = sg_client.get_security_groups(context, filters=filters)
        return len(res)

    def get_security_group(self, context, id, fields=None):
        res = sg_client.get_security_group(context, id)
        return self._fields(res, fields)

    def delete_security_group(self, context, id):
        sg_client.delete_security_group(context, id)

    def update_security_group(self, context, id, security_group):
        return sg_client.update_security_group(context, id, security_group)

    def create_security_group_rule(self, context, security_group_rule):
        return sg_client.create_security_group_rule(context,
                                                    security_group_rule)

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        res = sg_client.get_security_group_rules(context, filters=filters)
        return [self._fields(r, fields) for r in res]

    def get_security_group_rules_count(self, context, filters=None):
        res = sg_client.get_security_group_rules(context, filters=filters)
        return len(res)

    def get_security_group_rule(self, context, id, fields=None):
        res = sg_client.get_security_group_rule(context, id)
        return self._fields(res, fields)

    def delete_security_group_rule(self, context, id):
        sg_client.delete_security_group_rule(context, id)

    def _extend_port_security_group(self, context, ports, fields=None):
        """ Extend security group to port_dicts.

        Add security group information acquired from SG service to each port.
        When fields doesn't include secuirty_group,
        ports don't need security group, so skip access to SG service.
        """
        if fields and 'security_groups' not in fields:
            return [self._make_port_dict(port, fields) for port in ports]

        sg_port_ids = []
        net_port_ids = []
        for port in ports:
            if port['device_owner'].startswith('network:'):
                net_port_ids.append(port['id'])
            else:
                sg_port_ids.append(port['id'])

        if sg_port_ids:
            # fill sg_port_ids up to multiple of QUERY_ID_SIZE
            rest = len(sg_port_ids) % sg_client.QUERY_ID_SIZE
            if rest:
                rest = sg_client.QUERY_ID_SIZE - rest
                sg_port_ids += net_port_ids[:rest]
                net_port_ids = net_port_ids[rest:]

        pb_res = []
        if sg_port_ids:
            pb_res = sg_client.get_portbindings(context, sg_port_ids)
        if net_port_ids:
            try:
                res = sg_client.get_portbindings(context, net_port_ids)
                pb_res += res
            except Exception as ex:
                LOG.warn(_LW("Exception '%s' raised but ignored. "
                         "because all ports are network ports"), str(ex))

        sg_map = {}
        for pb in pb_res:
            sg_map[pb['id']] = [sg['id'] for sg in pb['security_groups']]

        port_res = []
        for port in ports:
            port_dict = self._make_port_dict(port, fields)
            port_dict['security_groups'] = sg_map.get(port['id'], [])
            port_res.append(port_dict)

        return port_res

    def _get_port_security_groups(self, context, port_id):
        """Get security groups which are associated with port."""
        pb_res = sg_client.get_portbinding(context, port_id)
        if not pb_res:
            return []
        return [sg['id'] for sg in pb_res['security_groups']]

    def _get_port_ips(self, port):
        """Get IPaddresses of port."""
        ips = [ip['ip_address'] for ip in port.get('fixed_ips', [])]
        ips += [ap['ip_address']
                for ap in port.get(addr_pair.ADDRESS_PAIRS, [])]
        return ips

    def _process_port_create_security_group(self, context, port,
                                            security_group_ids):
        """Create port-security group bindings in SG service.

        When security_group_ids is None,
        port don't need security group, so doesn't access SG service.
        """
        if not attr.is_attr_set(security_group_ids):
            port[ext_sg.SECURITYGROUPS] = []
            return

        pb = {'portbinding': {'id': port['id'],
                              'ips': self._get_port_ips(port),
                              'security_groups': list(security_group_ids)}}
        sg_client.create_portbinding(context, pb)

        # Convert to list as a set might be passed here and
        # this has to be serialized
        port[ext_sg.SECURITYGROUPS] = (security_group_ids and
                                       list(security_group_ids) or [])

    def _process_port_update_security_group(self, context, port):
        """Update port-security group bindings in SG service."""
        security_group_ids = port.get(ext_sg.SECURITYGROUPS, [])
        pb = {'portbinding': {'id': port['id'],
                              'ips': self._get_port_ips(port),
                              'security_groups': security_group_ids}}
        sg_client.update_portbinding(context, port['id'], pb)

    def _process_port_delete_security_group(self, context, port_id):
        """Delete port-security group bindings in SG service."""
        sg_client.delete_portbinding(context, port_id)

    def _ensure_default_security_group(self, context, tenant_id):
        """Create a default security group if one doesn't exist.

        :returns: the default security group id.
        """
        filters = {'name': ['default'], 'tenant_id': [tenant_id]}
        tmp_context_tenant_id = context.tenant_id
        context.tenant_id = tenant_id
        try:
            default_group = self.get_security_groups(context, filters)
            # it must exist.
            return default_group[0]['id']
        finally:
            context.tenant_id = tmp_context_tenant_id

    def _get_security_groups_on_port(self, context, port):
        """Check that all security groups on port belong to tenant.

        :returns: all security groups IDs on port belonging to tenant.
        """
        p = port['port']
        if not attr.is_attr_set(p.get(ext_sg.SECURITYGROUPS)):
            return
        if p.get('device_owner') and p['device_owner'].startswith('network:'):
            return

        port_sg = p.get(ext_sg.SECURITYGROUPS, [])
        filters = {'id': port_sg}
        tenant_id = p.get('tenant_id')
        if tenant_id:
            filters['tenant_id'] = [tenant_id]
        valid_groups = set(g['id'] for g in
                           self.get_security_groups(context, fields=['id'],
                                                    filters=filters))

        requested_groups = set(port_sg)
        port_sg_missing = requested_groups - valid_groups
        if port_sg_missing:
            raise ext_sg.SecurityGroupNotFound(id=', '.join(port_sg_missing))

        return requested_groups

    def _ensure_default_security_group_on_port(self, context, port):
        # we don't apply security groups for dhcp, router.
        if (port['port'].get('device_owner') and
                port['port']['device_owner'].startswith('network:')):
            return
        tenant_id = self._get_tenant_id_for_create(context,
                                                   port['port'])
        if attr.is_attr_set(port['port'].get(ext_sg.SECURITYGROUPS)):
            return self._get_security_groups_on_port(context, port)

        default_sg = self._ensure_default_security_group(context, tenant_id)
        sgids = [default_sg]
        port['port'][ext_sg.SECURITYGROUPS] = sgids
        return set(sgids)

    def _check_update_deletes_security_groups(self, port):
        """Return True if port has as a security group and it's value
        is either [] or not is_attr_set, otherwise return False.
        """

        if (ext_sg.SECURITYGROUPS in port['port'] and
            not (attr.is_attr_set(port['port'][ext_sg.SECURITYGROUPS])
                 and port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False

    def _check_update_has_security_groups(self, port):
        """Return True if port has as a security group and False if the
        security_group field is is_attr_set or [].
        """

        if (ext_sg.SECURITYGROUPS in port['port'] and
            (attr.is_attr_set(port['port'][ext_sg.SECURITYGROUPS]) and
             port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False

    def get_security_groups_by_ids(self, context, ids):
        return sg_client.get_security_groups_by_ids(context, ids)

    def update_security_group_on_port(self, context, id, port,
                                      original_port, updated_port):
        """Update security groups on port.

        This method adds security group data to updated_port.
        In addition, port has updated security groups or updated ips,
        calls _process_port_update_security_group to notify this changes.
        """
        need_notify_to_sg_service = False
        port_updates = port['port']
        if ext_sg.SECURITYGROUPS in port_updates:
            # validation check was done beforehand
            sgids = port_updates[ext_sg.SECURITYGROUPS]
            updated_port[ext_sg.SECURITYGROUPS] = (sgids and list(set(sgids))
                                                   or [])
            need_notify_to_sg_service = True
        else:
            updated_port[ext_sg.SECURITYGROUPS] = (
                self._get_port_security_groups(context, id))

        original_ips = self._get_port_ips(original_port)
        updated_ips = self._get_port_ips(updated_port)
        if not utils.compare_elements(original_ips, updated_ips):
            need_notify_to_sg_service = True
        if need_notify_to_sg_service:
            self._process_port_update_security_group(context, updated_port)

    def get_security_groups_minimal(self, context, filters=None, fields=None):
        """Get security groups in minimal composition of response.

        This method gets security group data in minimal composition.
        It contains minimum necessary information
        to compare security group on SG service with on Midonet.
        """
        if filters is None:
            filters = {}
        filters['fields'] = 'minimal'
        res = self.get_security_groups(context, filters=filters, fields=fields)
        return res

    def get_security_groups_from_midonet(self, context, fields=None):
        res = self.client.get_security_groups()
        if fields:
            return [self._fields(sg, fields) for sg in res]
        return res

    def get_security_group_members(self, context, sgid):
        res = self.client.get_ipaddr_group_addrs(sgid)
        ip_list = []
        for ipaddr in res:
            if ipaddr.get('addr', None):
                ip_list.append(ipaddr['addr'])

        LOG.debug("Got security group members from midonet : %s", ip_list)
        return ip_list

    @log_helpers.log_method_call
    def _notify_created_security_group(self, context, sgids):
        """Create security groups on Midonet."""
        sgs = self.get_security_groups(context, filters={'id': sgids})
        for sg in sgs:
            try:
                self.client.create_security_group_precommit(context, sg)
                self.client.create_security_group_postcommit(sg)
            except webob.exc.HTTPConflict:
                    LOG.info(_("Conflict security group on midonet: Already "
                               "created %s"), sg['id'])
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to create MidoNet resources for "
                                  "sg %(sg)r, error=%(err)r"),
                              {"sg": sg, "err": ex})
        return sgids

    @log_helpers.log_method_call
    def _notify_deleted_security_group(self, context, ids):
        """Delete security groups on Midonet."""
        for id in ids:
            self.client.delete_security_group_precommit(context, id)
            try:
                self.client.delete_security_group_postcommit(id)
            except webob.exc.HTTPNotFound:
                LOG.info(_("Not found security group on midonet: Already "
                           "deleted %s"), id)
            except Exception as ex:
                LOG.error(_LE("Failed to delete a security group. "
                              "security group: %(id)s, error: %(err)s"),
                          {'id': id, 'err': ex})

    @log_helpers.log_method_call
    def _notify_created_security_group_rule(self, context, rule_ids):
        """Create security group rules on Midonet."""
        rules = self.get_security_group_rules(context,
                                              filters={'id': rule_ids})
        for rule in rules:
            self.client.create_security_group_rule_precommit(context, rule)
            try:
                self.client.create_security_group_rule_postcommit(rule)
            except webob.exc.HTTPConflict:
                LOG.info(_("Conflict security group rule on midonet: "
                           "Already created %s"), rule)
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to create security group rule. "
                                  "security group rule: "
                                  "%(rule)s, error: %(err)s"),
                              {'rule': rule, 'err': ex})
        return rule_ids

    @log_helpers.log_method_call
    def _notify_deleted_security_group_rule(self, context, ids):
        """Delete security group rules on Midonet."""
        for id in ids:
            self.client.delete_security_group_rule_precommit(context, id)
            try:
                self.client.delete_security_group_rule_postcommit(id)
            except webob.exc.HTTPNotFound:
                LOG.info(_("Not found security group rule on midonet: "
                           "Already deleted %s"), id)
            except Exception as ex:
                LOG.error(_LE("Failed to delete a security group rule. "
                              "security group rule: %(id)s, error: %(err)s"),
                          {'id': id, 'err': ex})

    @log_helpers.log_method_call
    def _notify_created_security_group_member(self, context, id, ips):
        """Create security group members on Midonet."""
        ip_version = 4
        for ip in ips:
            ipaddr = {'addr': ip, 'ipAddrGroupId': id, 'version': ip_version}
            try:
                self.client.create_ipaddr_group_addr(ipaddr)
            except webob.exc.HTTPConflict:
                LOG.info(_("Conflict security group member on midonet: "
                           "Already created member(security group: %(sgid)s, "
                           "ip : %(ip)s)"), {'sgid': id, 'ip': ip})
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to create security group member. "
                                  "security group: %(sgid)s, "
                                  "ipaddr: %(ipaddr)s, error: %(err)s"),
                              {'sgid': id, 'ipaddr': ipaddr, 'err': ex})

    @log_helpers.log_method_call
    def _notify_deleted_security_group_member(self, context, id, ips):
        """Delete security group members on Midonet."""
        ip_version = '4'
        for ip in ips:
            try:
                self.client.delete_ipaddr_group_addr(id, ip_version, ip)
            except webob.exc.HTTPNotFound:
                LOG.info(_("Not found security group member on midonet: "
                           "Already deleted member(security group: %(sgid)s, "
                           "ip: %(ip)s)"), {'sgid': id, 'ip': ip})
                continue
            except Exception as ex:
                LOG.error(_LE("Falied to delete a security group member. "
                              "security group: %(sgid)s, ip: %(ip)s, "
                              "error: %(err)s"),
                          {'sgid': id, 'ip': ip, 'err': ex})

    @log_helpers.log_method_call
    def _notify_security_group_member_updated(self, context, map):
        """Classify security group member into created and deleted."""
        for id in map.keys():
            mido_ip_list = self.get_security_group_members(context, id)
            create_ips = set(map[id]) - set(mido_ip_list)
            if create_ips:
                self._notify_created_security_group_member(context,
                                                           id, create_ips)
            delete_ips = set(mido_ip_list) - set(map[id])
            if delete_ips:
                self._notify_deleted_security_group_member(context,
                                                           id, delete_ips)

    def _make_security_group_map(self, sgs):
        sg_map = {}
        for sg in sgs:
            sg_map[sg['id']] = sg
        return sg_map

    def _check_security_group_changes(self, context, change_ids):
        """Classify security group into created and deleted."""
        sgs = self.get_security_groups_minimal(context,
                                               filters={'id': change_ids})
        sg_map = self._make_security_group_map(sgs)

        create_sgids = set()
        delete_sgids = set()
        for id in change_ids:
            if id in sg_map.keys():
                create_sgids.add(id)
            else:
                delete_sgids.add(id)
        return (create_sgids, delete_sgids)

    @log_helpers.log_method_call
    def notify_security_group_changes(self, context, change_ids):
        create_sgids, delete_sgids = (
            self._check_security_group_changes(context, change_ids))
        if create_sgids:
            self._notify_created_security_group(context, create_sgids)
        if delete_sgids:
            self._notify_deleted_security_group(context, delete_sgids)

    def _make_security_group_rule_map(self, sgs=None, sg_map=None):
        sg_rule_map = {}
        if sgs:
            for sg in sgs:
                sg_rule_map[sg['id']] = [rule.get('id') for rule
                                         in sg.get('security_group_rules')]
            return sg_rule_map
        if sg_map:
            for id in sg_map.keys():
                sg_rule_map[id] = [rule.get('id') for rule
                                   in sg_map[id].get('security_group_rules')]
        return sg_rule_map

    def _check_security_group_rule_updated(self, context, sgids):
        sgs = self.get_security_groups_minimal(context, filters={'id': sgids})
        sg_rule_map = {}
        for sg in sgs:
            sg_rule_map[sg['id']] = sg['security_group_rules']
        return sg_rule_map

    def _make_mido_rule_map(self, context):
        fields = ["id", "security_group_rules"]
        mido_sgs = self.get_security_groups_from_midonet(context, fields)
        mido_rule_map = self._make_security_group_rule_map(sgs=mido_sgs)
        return mido_rule_map

    @log_helpers.log_method_call
    def notify_security_group_rules_updated(self, context, sgids):
        sg_rule_map = self._check_security_group_rule_updated(context, sgids)
        mido_rule_map = self._make_mido_rule_map(context)
        self._notify_security_group_rule_updated(context,
                                                 sg_rule_map, mido_rule_map)

    @log_helpers.log_method_call
    def _notify_security_group_rule_updated(self, context,
                                            sg_rule_map, mido_rule_map):
        """Classify security group rule into created and deleted"""
        create_rules = []
        delete_rules = []
        for id in sg_rule_map.keys():
            need_create = set(sg_rule_map[id]) - set(mido_rule_map[id])
            if need_create:
                create_rules.extend(need_create)
            need_delete = set(mido_rule_map[id]) - set(sg_rule_map[id])
            if need_delete:
                delete_rules.extend(need_delete)

        if create_rules:
            self._notify_created_security_group_rule(context, create_rules)
        if delete_rules:
            self._notify_deleted_security_group_rule(context, delete_rules)

    def _make_sg_ip_map(self, context, sgids=None, sg_map=None):
        sg_ip_map = {}
        sgs = {}
        if sgids:
            sgs = self.get_security_groups_minimal(context,
                                                   filters={'id': sgids})
        if sg_map:
            sgs = sg_map.values()
        for sg in sgs:
            sg_ip_map[sg['id']] = sg.get('ips')
        return sg_ip_map

    @log_helpers.log_method_call
    def notify_security_group_member_updated(self, context, remote_sgids=None):
        sg_ip_map = {}
        if remote_sgids:
            sg_ip_map = self._make_sg_ip_map(context, sgids=remote_sgids)

        self._notify_security_group_member_updated(context, sg_ip_map)

    @log_helpers.log_method_call
    def create_security_group_update(self, context, security_group_update):
        update = security_group_update['security_group_update']
        change_ids = update.get('security_group_changes')
        if change_ids:
            self.notify_security_group_changes(context, change_ids=change_ids)
        sgids = update.get('security_groups')
        if sgids:
            self.notify_security_group_rules_updated(context, sgids=sgids)
        remote_sgids = update.get('security_group_source_groups')
        if remote_sgids:
            self.notify_security_group_member_updated(
                context, remote_sgids=remote_sgids)
        return update

    @log_helpers.log_method_call
    def sync_security_groups(self, context, create_sgids, delete_sgids):
        if create_sgids:
            self._notify_created_security_group(context, create_sgids)
        if delete_sgids:
            self._notify_deleted_security_group(context, delete_sgids)

    @log_helpers.log_method_call
    def sync_security_group_rules(self, context, sg_map, mido_sg_map):
        sg_rule_map = {}
        for k, v in sg_map.iteritems():
            sg_rule_map[k] = v['security_group_rules']
        mido_rule_map = self._make_security_group_rule_map(sg_map=mido_sg_map)
        self._notify_security_group_rule_updated(context,
                                                 sg_rule_map, mido_rule_map)

    @log_helpers.log_method_call
    def sync_security_group_members(self, context, sg_map):
        sg_ip_map = self._make_sg_ip_map(context, sg_map=sg_map)
        self._notify_security_group_member_updated(context, sg_ip_map)
