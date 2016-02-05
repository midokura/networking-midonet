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

from oslo_log import log as logging

from neutron.common import exceptions as n_exc
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron import i18n
from neutron import manager

LOG = logging.getLogger(__name__)
_LE = i18n._LE
_LW = i18n._LW

QUERY_ID_SIZE = 200

sg_cache = {}
default_sg_cache = {}


class LocalSGService(db_base_plugin_v2.NeutronDbPluginV2,
                     addr_pair_db.AllowedAddressPairsMixin,
                     sg_db.SecurityGroupDbMixin):
    regional_sg = True

    def __init__(self):
        pass

    def create_security_group_update(self, context, data):
        pass


local_sg_service = LocalSGService()


def _notify_update(context,
                   security_group_changes, security_groups, source_groups):
    plugin = manager.NeutronManager.get_plugin()
    security_group_update = {}
    if security_group_changes:
        security_group_update['security_group_changes'] = (
                                                        security_group_changes)
    if security_groups:
        security_group_update['security_groups'] = security_groups
    if source_groups:
        security_group_update['security_group_source_groups'] = source_groups
    LOG.info(_("create_security_group_update req: %s"), security_group_update)
    plugin.create_security_group_update(context, {'security_group_update':
                                                  security_group_update})


def get_default_security_groups(context, tenant_id):
    LOG.info(_("get_default_security_groups called"))
    filters = {'name': ['default']}
    res = local_sg_service.get_security_groups(context, filters=filters)
    LOG.info(_("get_default_security_groups res: %s"), res)
    dsg_id = [dsg['id'] for dsg in res if dsg['tenant_id'] == tenant_id]
    if dsg_id:
        return dsg_id[0]
    return None


def create_security_group(context, security_group):
    LOG.info(_("create_security_group req: %s"), security_group)
    res = local_sg_service.create_security_group(context, security_group)
    LOG.info(_("create_security_group res: %s"), res)
    changes = [res['id']]
    tenant_id = res['tenant_id']
    LOG.info(_("default_sg_cache : %s"), default_sg_cache)
    if not (tenant_id in default_sg_cache.keys()):
        default_sg_id = get_default_security_groups(context, tenant_id)
        changes.append(default_sg_id)
        default_sg_cache[tenant_id] = default_sg_id
    _notify_update(context, changes, None, None)
    return res


def update_security_group(context, id, security_group):
    LOG.info(_("update_security_group id, req: %(id)s %(sg)s"),
             {'id': id, 'sg': security_group})
    res = local_sg_service.update_security_group(context, id, security_group)
    LOG.info(_("update_security_group res: %s"), res)
    return res


def delete_security_group(context, id):
    LOG.info(_("delete_security_group id: %s"), id)
    local_sg_service.delete_security_group(context, id)
    delete_dsg_tenant = [k for k, v in default_sg_cache.iteritems() if id == v]
    if delete_dsg_tenant:
        default_sg_cache.pop(delete_dsg_tenant[0])
    _notify_update(context, [id], None, None)


def get_security_groups(context, filters=None, fields=None):
    LOG.info(_("get_security_groups called"))
    tenant_id = context.tenant_id
    if not (tenant_id in default_sg_cache.keys()):
        default_sg_id = get_default_security_groups(context, tenant_id)
        if default_sg_id:
            default_sg_cache[tenant_id] = default_sg_id
            _notify_update(context, [default_sg_id], None, None)
    if filters:
        LOG.info(_("filters %s "), filters)
        if 'minimal' == filters.get('fields', None):
            filters.pop('fields')
            sgs = local_sg_service.get_security_groups(context,
                                                       filters=filters)
            sgs_with_ip = [_get_security_group_with_ips(context, sg['id'])
                   for sg in sgs]
            for sg in sgs_with_ip:
                rule_ids = []
                rules = sg.get('security_group_rules', [])
                for rule in rules:
                    if rule.get('id', None):
                        rule_ids.append(rule['id'])
                sg['security_group_rules'] = rule_ids
            LOG.info(_("get_security_groups_minimal res: %s"), sgs_with_ip)
            return sgs_with_ip
    res = local_sg_service.get_security_groups(context,
                                               filters=filters, fields=fields)
    LOG.info(_("get_security_groups res: %s"), res)

    return res


def get_security_group(context, id):
    LOG.info(_("get_security_group id: %s"), id)
    res = local_sg_service.get_security_group(context, id)
    LOG.info(_("get_security_group res: %s"), res)
    return res


def create_security_group_rule(context, security_group_rule):
    LOG.info(_("create_security_group_rule req: %s"), security_group_rule)
    res = local_sg_service.create_security_group_rule(context,
                                                      security_group_rule)
    # notify update regardless of port-sg-bindings
    sg_id = res['security_group_id']
    _notify_update(context, None, [sg_id], None)

    LOG.info(_("create_security_group_rule res: %s"), res)
    return res


def delete_security_group_rule(context, id):
    LOG.info(_("delete_security_group_rule id: %s"), id)
    res = local_sg_service.get_security_group_rule(context, id)
    sg_id = res['security_group_id']
    local_sg_service.delete_security_group_rule(context, id)
    _notify_update(context, None, [sg_id], None)


def get_security_group_rules(context, filters=None):
    LOG.info(_("get_security_group_rules called"))
    res = local_sg_service.get_security_group_rules(context, filters=filters)
    LOG.info(_("get_security_group_rules res: %s"), res)
    return res


def get_security_group_rule(context, id):
    LOG.info(_("get_security_group_rule id: %s"), id)
    res = local_sg_service.get_security_group_rule(context, id)
    LOG.info(_("get_security_group_rule res: %s"), res)
    return res


def create_portbinding(context, portbinding):
    LOG.info(_("create_portbinding req: %s"), portbinding)
    portbinding = portbinding['portbinding']
    port_id = portbinding['id']
    for sg_id in portbinding['security_groups']:
        local_sg_service._create_port_security_group_binding(context, port_id,
                                                             sg_id)
    # notify update
    _notify_update(context, None, None, portbinding['security_groups'])
    sg_cache[port_id] = portbinding['security_groups']

    return portbinding


def update_portbinding(context, id, portbinding):
    LOG.info(_("update_portbinding req: %s"), portbinding)
    portbinding = portbinding['portbinding']
    filters = {'port_id': [id]}
    bindings = local_sg_service._get_port_security_group_bindings(context,
                                                                  filters)
    orig_sg_ids = [binding['security_group_id'] for binding in bindings]

    # do simple. delete all and re-create.
    local_sg_service._delete_port_security_group_bindings(context, id)
    for sg_id in portbinding['security_groups']:
        local_sg_service._create_port_security_group_binding(context, id,
                                                             sg_id)
    # notify update
    modified = set(orig_sg_ids) | set(portbinding['security_groups'])
    _notify_update(context, None, None, list(modified))
    sg_cache[id] = portbinding['security_groups']

    return portbinding


def delete_portbinding(context, id):
    LOG.info(_("delete_portbinding id: %s"), id)
    # it is not necessary actually since portbindings was deleted by cascade
    # when port was deleted.
    local_sg_service._delete_port_security_group_bindings(context, id)
    # so this is why sg_cache is necessary.
    sg_ids = sg_cache.get(id)
    _notify_update(context, None, None, sg_ids)
    if id in sg_cache:
        del sg_cache[id]


def _get_port_ips(port):
    ips = [ip['ip_address'] for ip in port.get('fixed_ips', [])]
    ips += [ap['ip_address']
            for ap in port.get(addr_pair.ADDRESS_PAIRS, [])]
    return ips


def _get_security_group_with_ips(context, sg_id):
    try:
        sg = local_sg_service.get_security_group(context, sg_id)
    except Exception:
        LOG.info(_("Failed to get_security_group: %s"), id)
        return
    filters = {'security_group_id': [sg_id]}
    bindings = local_sg_service._get_port_security_group_bindings(context,
                                                                  filters)
    ips = set()
    for binding in bindings:
        port = local_sg_service.get_port(context, binding['port_id'])
        ips |= set(_get_port_ips(port))
    sg['ips'] = list(ips)

    return sg


def _get_portbinding(context, id):
    filters = {'port_id': [id]}
    bindings = local_sg_service._get_port_security_group_bindings(context,
                                                                  filters)
    sg_ids = [binding['security_group_id'] for binding in bindings]
    security_groups = [_get_security_group_with_ips(context, sg_id)
                       for sg_id in sg_ids]
    port = local_sg_service.get_port(context, id)
    ips = _get_port_ips(port)
    portbinding = {'id': id,
                   'ips': ips,
                   'security_groups': security_groups}
    return portbinding


def get_portbinding(context, id):
    LOG.info(_("get_portbinding id: %s"), id)
    try:
        res = _get_portbinding(context, id)
    except n_exc.NotFound:
        return
    LOG.info(_("get_portbinding res: %s"), res)
    return res


def get_portbindings(context, port_ids=None):
    LOG.info(_("get_portbindings ids: %s"), port_ids)
    if not port_ids:
        return []
    res = [_get_portbinding(context, port_id) for port_id in port_ids]
    LOG.info(_("get_portbindings res: %s"), res)
    return res


def get_security_groups_by_ids(context, ids):
    LOG.info(_("get_security_groups_by_ids ids: %s"), ids)
    res = []
    for sg_id in ids:
        sg = _get_security_group_with_ips(context, sg_id)
        if sg:
            res.append(sg)
    # res = [_get_security_group_with_ips(context, sg_id) for sg_id in ids]
    LOG.info(_("get_security_groups_by_ids res: %s"), res)
    return res


def create_security_group_without_notify(context, security_group):
    LOG.info(_("create_security_group req: %s"), security_group)
    res = local_sg_service.create_security_group(context, security_group)
    LOG.info(_("create_security_group res: %s"), res)
    return res


def delete_security_group_without_notify(context, id):
    LOG.info(_("delete_security_group id: %s"), id)
    local_sg_service.delete_security_group(context, id)


def create_security_group_rule_without_notify(context, security_group_rule):
    LOG.info(_("create_security_group_rule req: %s"), security_group_rule)
    res = local_sg_service.create_security_group_rule(context,
                                                      security_group_rule)
    LOG.info(_("create_security_group_rule res: %s"), res)
    return res


def delete_security_group_rule_without_notify(context, id):
    LOG.info(_("delete_security_group_rule id: %s"), id)
    local_sg_service.delete_security_group_rule(context, id)


def create_portbinding_without_notify(context, portbinding):
    LOG.info(_("create_portbinding req: %s"), portbinding)
    portbinding = portbinding['portbinding']
    port_id = portbinding['id']
    for sg_id in portbinding['security_groups']:
        local_sg_service._create_port_security_group_binding(context,
                                                             port_id, sg_id)
    sg_cache[port_id] = portbinding['security_groups']
    return portbinding


def update_portbinding_without_notify(context, id, portbinding):
    LOG.info(_("update_portbinding req: %s"), portbinding)
    portbinding = portbinding['portbinding']
    local_sg_service._delete_port_security_group_bindings(context, id)
    for sg_id in portbinding['security_groups']:
        local_sg_service._create_port_security_group_binding(context, id,
                                                             sg_id)
    sg_cache[id] = portbinding['security_groups']
    return portbinding


def delete_portbinding_without_notify(context, id):
    LOG.info(_("delete_portbinding id: %s"), id)
    # it is not necessary actually since portbindings was deleted by cascade
    # when port was deleted.
    local_sg_service._delete_port_security_group_bindings(context, id)
    # so this is why sg_cache is necessary.
    if id in sg_cache:
        del sg_cache[id]
