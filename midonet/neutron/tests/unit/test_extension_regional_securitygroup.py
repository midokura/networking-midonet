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

import contextlib
import copy
import mock
import webob.exc

from midonet.neutron.extensions import regional_securitygroup as ext_rsg
from midonet.neutron.tests.unit import sg_client_mock as sgc_mock
from midonet.neutron.tests.unit import test_midonet_rsg_plugin as test_mn_rsg

from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron import context as ncontext
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.tests.unit.api import test_extensions as test_ex
from neutron.tests.unit.extensions import test_securitygroup


# NOTE(RegionalSG):
# neutron.policy._is_attribute_explictly_set method uses "update" string
# in action, so in spite of create action security_group_update action
# will be judged as update action.
# So this method is mocked by fixed method.
def _is_attribute_explicitly_set(attribute_name, resource, target, action):
    """Verify that an attribute is present and is explicitly set."""
    if const.ATTRIBUTES_TO_UPDATE in target:
        # In the case of update, the function should not pay attention to a
        # default value of an attribute, but check whether it was explicitly
        # marked as being updated instead.
        return (attribute_name in target[const.ATTRIBUTES_TO_UPDATE] and
                target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED)
    return ('default' in resource[attribute_name] and
            attribute_name in target and
            target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED and
            target[attribute_name] != resource[attribute_name]['default'])


class RegionalSecurityGroupExtensionManager(
    test_securitygroup.SecurityGroupTestExtensionManager):

    def get_resources(self):
        res = super(RegionalSecurityGroupExtensionManager,
                    self).get_resources()
        return res + ext_rsg.Regional_securitygroup.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class RegionalSecurityGoupTestCase(
    test_mn_rsg.MidonetRegionalSGPluginTestCase,
    test_securitygroup.SecurityGroupsTestCase):

    def setUp(self):
        ext_mgr = RegionalSecurityGroupExtensionManager()
        super(RegionalSecurityGoupTestCase, self).setUp()
        self.ext_api = test_ex.setup_extensions_middleware(ext_mgr)
        _is_attribute_explicitly_set_patcher = (
            mock.patch('neutron.policy._is_attribute_explicitly_set'))
        _is_attribute_explicitly_set_patcher.start().side_effect = (
            _is_attribute_explicitly_set)
        self.plugin = manager.NeutronManager.get_plugin()

    def _create_security_group_update(self, sg_changes,
                                      sgs, sg_src_grp, context=None):
        data = {'security_group_update':
                {'security_group_changes': sg_changes,
                 'security_groups': sgs,
                 'security_group_source_groups': sg_src_grp
                 }
                }
        updates_req = self.new_create_request('security-group-updates',
                                              data, self.fmt, context=context)
        return updates_req.get_response(self.ext_api)

    def _make_security_group_update(self, sg_changes, sgs,
                                    sg_src_grp, context=None):
        if context is None:
            context = ncontext.get_admin_context()
        res = self._create_security_group_update(sg_changes, sgs,
                                                 sg_src_grp, context=context)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    @contextlib.contextmanager
    def security_group_update(self, sg_changes=[],
                              sgs=[], sg_src_grp=[], context=None):
        updates = self._make_security_group_update(sg_changes, sgs,
                                                   sg_src_grp, context=context)
        yield updates


class TestRegionalSecurityGroup(RegionalSecurityGoupTestCase):
    def test_create_security_group_update_only_sg_changes(self):
        ctxt = ncontext.Context('', 'somebody')
        body = {'security_group': {'name': 'webservers',
                                   'description': 'webservers'}}
        sg = sgc_mock.create_security_group_without_notify(ctxt, body)
        id = sg['id']
        expected = {'security_group_changes': [id],
                    'security_groups': [],
                    'security_group_source_groups': []}
        with self.security_group_update(sg_changes=[id],
                                        context=ctxt) as updates:
            for k, v in expected.iteritems():
                self.assertEqual(updates['security_group_update'][k], v)

    def test_create_security_group_update_only_sgs(self):
        with self.security_group('webservers', 'webservers') as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            body = {'security_group_rule': {'security_group_id': sg_id,
                                            'protocol': 'TCP',
                                            'direction': "ingress",
                                            'ethertype': 'ipv4',
                                            'port_range_min': None,
                                            'port_range_max': None,
                                            'remote_ip_prefix': None,
                                            'remote_group_id': None,
                                            'tenant_id': tenant_id
                                            }}
            ctxt = ncontext.Context('', tenant_id)
            sgc_mock.create_security_group_rule_without_notify(ctxt, body)
            expected = {'security_group_changes': [],
                        'security_groups': [sg_id],
                        'security_group_source_groups': []}
            with self.security_group_update(sgs=[sg_id],
                                            context=ctxt) as updates:
                for k, v in expected.iteritems():
                    self.assertEqual(updates['security_group_update'][k], v)

    def test_create_security_group_update_only_sg_src_grp(self):
        with self.security_group('webservers', 'webservers') as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            ctxt = ncontext.Context('', tenant_id)
            sg['security_group']['ips'] = ['192.168.10.10', '192.168.10.11']
            expected = {'security_group_changes': [],
                        'security_groups': [],
                        'security_group_source_groups': [sg_id]}
            get_sg_mini = 'get_security_groups_minimal'
            with mock.patch.object(self.plugin, get_sg_mini) as get_sg:
                get_sg.return_value = [sg['security_group']]
                with self.security_group_update(sg_src_grp=[sg_id],
                                                context=ctxt) as updates:
                    for k, v in expected.iteritems():
                        self.assertEqual(
                            updates['security_group_update'][k], v)

    def test_create_security_group_update_no_updates(self):
        with self.security_group('webservers', 'webservers') as sg:
            tenant_id = sg['security_group']['tenant_id']
            ctxt = ncontext.Context('', tenant_id)
            expected = {'security_group_changes': [],
                        'security_groups': [],
                        'security_group_source_groups': []}
            with self.security_group_update(context=ctxt) as updates:
                for k, v in expected.iteritems():
                    self.assertEqual(updates['security_group_update'][k], v)

    def test_create_security_group_update_specified_all(self):
        with self.security_group('webservers', 'webservers') as sg1:
            with self.security_group('webservers2', 'webservers2') as sg2:
                sg_id1 = sg1['security_group']['id']
                tenant_id = sg1['security_group']['tenant_id']
                default_rule_id = (
                    sg1['security_group']['security_group_rules'][0]['id'])
                # sg1: notify to delete default rule
                ctxt = ncontext.Context('', tenant_id)
                sgc_mock.delete_security_group_rule_without_notify(
                    ctxt, default_rule_id)
                # sg2: notify to change ipaddr but there are no changes
                sg_id2 = sg2['security_group']['id']
                # sg3: notify to create sg3
                body = {'security_group': {'name': 'webservers',
                                           'description': 'webservers'}}
                sg3 = sgc_mock.create_security_group_without_notify(ctxt, body)
                sg_id3 = sg3['id']
                expected = {'security_group_changes': [sg_id3],
                            'security_groups': [sg_id1],
                            'security_group_source_groups': [sg_id2]}
                with self.security_group_update(
                    sg_changes=[sg_id3], sgs=[sg_id1],
                        sg_src_grp=[sg_id2], context=ctxt) as updates:
                    for k, v in expected.iteritems():
                        self.assertEqual(updates['security_group_update'][k],
                                         v)

    # midonet.neutron.db.regional_securitygroup_db test
    def test_get_security_groups_minimal(self):
        with self.security_group('webservers', 'webservers'):
            with self.security_group('webservers2', 'webservers2'):
                ctxt = ncontext.get_admin_context()
                sgs = self.plugin.get_security_groups_minimal(ctxt)
                self.assertEqual(3, len(sgs))
                self.assertIn('id', sgs[0].keys())
                self.assertIn('ips', sgs[0].keys())
                self.assertIn('security_group_rules', sgs[0].keys())

    def test_get_security_groups_minimal_filters(self):
        with self.security_group('webservers', 'webservers') as sg1:
            with self.security_group('webservers2', 'webservers2'):
                securitygroup = sg1['security_group']
                rule_id1 = securitygroup['security_group_rules'][0]['id']
                rule_id2 = securitygroup['security_group_rules'][1]['id']
                ctxt = ncontext.get_admin_context()
                filters = {'id': [securitygroup['id']]}
                sgs = self.plugin.get_security_groups_minimal(ctxt,
                                                              filters=filters)
                self.assertEqual(1, len(sgs))
                self.assertEqual(set([rule_id1, rule_id2]),
                                 set(sgs[0]['security_group_rules']))

    def test_get_security_groups_minimal_fields(self):
        with self.security_group('webservers', 'webservers'):
            with self.security_group('webservers2', 'webservers2'):
                ctxt = ncontext.get_admin_context()
                fields = ['id', 'ips']
                sgs = self.plugin.get_security_groups_minimal(ctxt,
                                                              fields=fields)
                self.assertEqual(3, len(sgs))
                self.assertIn('id', sgs[0].keys())
                self.assertIn('ips', sgs[0].keys())
                self.assertNotIn('security_group_rules', sgs[0].keys())

    def test_get_security_groups_from_midonet(self):
        with self.security_group('webservers', 'webservers'):
            with self.security_group('webservers2', 'webservers2'):
                ctxt = ncontext.get_admin_context()
                sgs = self.plugin.get_security_groups_from_midonet(ctxt)
                self.assertEqual(3, len(sgs))
                self.assertIn('id', sgs[0].keys())
                self.assertIn('security_group_rules', sgs[0].keys())

    def test_get_security_groups_from_midonet_fields(self):
        with self.security_group('webservers', 'webservers'):
            with self.security_group('webservers2', 'webservers2'):
                ctxt = ncontext.get_admin_context()
                fields = ['id']
                sgs = self.plugin.get_security_groups_from_midonet(
                                                        ctxt, fields=fields)
                self.assertEqual(3, len(sgs))
                self.assertIn('id', sgs[0].keys())
                self.assertNotIn('security_group_rules', sgs[0].keys())

    def test_get_security_group_members(self):
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    ip_address = port['port']['fixed_ips'][0]['ip_address']
                    ctxt = ncontext.get_admin_context()
                    members = self.plugin.get_security_group_members(ctxt,
                                                                     sgid)
                    self.assertEqual(members, [ip_address])

    def test_extend_port_security_group(self):
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    p = port['port']
                    ctxt = ncontext.get_admin_context()
                    port_db = self.plugin._get_port(ctxt, p['id'])
                    port_res = self.plugin._extend_port_security_group(
                                                                    ctxt,
                                                                    [port_db])
                    self.assertEqual(p['id'], port_res[0]['id'])
                    self.assertEqual(p['fixed_ips'], port_res[0]['fixed_ips'])
                    self.assertEqual(p['security_groups'],
                                     port_res[0]['security_groups'])

    def test_extend_port_security_group_no_sg_field(self):
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    p = port['port']
                    ctxt = ncontext.get_admin_context()
                    fields = ['id', 'fixed_ips']
                    port_db = self.plugin._get_port(ctxt, p['id'])
                    port_res = self.plugin._extend_port_security_group(
                                                                ctxt,
                                                                [port_db],
                                                                fields=fields)
                    self.assertEqual(p['id'], port_res[0]['id'])
                    self.assertEqual(p['fixed_ips'], port_res[0]['fixed_ips'])
                    self.assertNotIn('security_groups', port_res[0].keys())

    def test_extend_port_security_group_network_port(self):
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub,
                               device_owner=const.DEVICE_OWNER_DHCP) as port:
                    p = port['port']
                    ctxt = ncontext.get_admin_context()
                    port_db = self.plugin._get_port(ctxt, p['id'])
                    port_res = self.plugin._extend_port_security_group(
                                                                    ctxt,
                                                                    [port_db])
                    self.assertEqual(p['id'], port_res[0]['id'])
                    self.assertEqual(p['fixed_ips'], port_res[0]['fixed_ips'])
                    self.assertEqual([], port_res[0]['security_groups'])
                    # update port with security_group
                    data = {'port': {'name': p['name'],
                                     'fixed_ips': p['fixed_ips'],
                                     'security_groups': [sgid]}}
                    req = self.new_update_request('ports', data, p['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    updated_port_db = self.plugin._get_port(ctxt, p['id'])
                    port_res = self.plugin._extend_port_security_group(
                                                                    ctxt,
                                                                    [port_db])
                    self.assertEqual(p['id'], port_res[0]['id'])
                    self.assertEqual(p['fixed_ips'], port_res[0]['fixed_ips'])
                    self.assertEqual(res['port']['security_groups'],
                                     port_res[0]['security_groups'])
                    # in case of HTTPError
                    get_portbindings = ('midonet.neutron.client.sg_client.'
                                        'get_portbindings')
                    with mock.patch(get_portbindings) as get_pb:
                        get_pb.side_effect = webob.exc.HTTPError
                        port_res = self.plugin._extend_port_security_group(
                                                            ctxt,
                                                            [updated_port_db])
                        self.assertEqual(p['id'], port_res[0]['id'])
                        self.assertEqual(p['fixed_ips'],
                                         port_res[0]['fixed_ips'])
                        self.assertEqual([], port_res[0]['security_groups'])

    def test_get_port_security_groups_port_not_exist(self):
        with self.network() as net, self.subnet(net):
            with self.security_group('webservers', 'webservers'):
                ctxt = ncontext.get_admin_context()
                port_id = 'dummy_id'
                res = self.plugin._get_port_security_groups(ctxt, port_id)
                self.assertEqual([], res)

    def test_get_port_ips(self):
        with self.network() as net, self.subnet(net) as sub:
            with self.port(subnet=sub) as port:
                p = port['port']
                ips = self.plugin._get_port_ips(p)
                self.assertEqual(1, len(ips))

    def test_get_port_ips_with_allow_address_pairs(self):
        with self.network() as net, self.subnet(net):
            address_pairs = [{'mac_address': '00:00:00:00:11:11',
                              'ip_address': '10.0.0.100'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_pair.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS],
                             address_pairs)
            ips = self.plugin._get_port_ips(port['port'])
            self.assertEqual(2, len(ips))
            self._delete('ports', port['port']['id'])

    def test_process_port_create_security_group_not_is_attr_set(self):
        with self.network() as net, self.subnet(net):
            ctxt = ncontext.get_admin_context()
            port = {'port': {}}
            self.plugin._process_port_create_security_group(ctxt, port, None)
            self.assertEqual([], port['security_groups'])

    def test_ensure_default_security_group(self):
        with self.network() as net:
            tenant_id = net['network']['tenant_id']
            ctxt = ncontext.get_admin_context()
            admin_tenant = ctxt.tenant_id
            default_group = self.plugin._ensure_default_security_group(
                                                            ctxt, tenant_id)
            self.assertIsNotNone(default_group)
            self.assertEqual(admin_tenant, ctxt.tenant_id)

    def test_get_security_group_on_port_witout_security_group(self):
        ctxt = ncontext.get_admin_context()
        port = {'port': {}}
        res = self.plugin._get_security_groups_on_port(ctxt, port)
        self.assertIsNone(res)

    def test_get_security_group_on_port_to_network_port(self):
        ctxt = ncontext.get_admin_context()
        port = {'port': {'device_owner': const.DEVICE_OWNER_ROUTER_GW}}
        res = self.plugin._get_security_groups_on_port(ctxt, port)
        self.assertIsNone(res)

    def test_get_security_group_on_port_missing_security_group(self):
        get_security_groups = ('midonet.neutron.client.sg_client.'
                              'get_security_groups')
        with mock.patch(get_security_groups) as get_sgs:
            get_sgs.return_value = []
            ctxt = ncontext.get_admin_context()
            port = {'port': {'security_groups': ['test_id']}}
            self.assertRaises(ext_sg.SecurityGroupNotFound,
                              self.plugin._get_security_groups_on_port,
                              ctxt, port)

    def test_ensure_default_security_group_on_port_to_network_port(self):
        ctxt = ncontext.get_admin_context()
        port = {'port': {'device_owner': const.DEVICE_OWNER_DHCP}}
        res = self.plugin._ensure_default_security_group_on_port(ctxt, port)
        self.assertIsNone(res)

    def test_update_security_group_on_port_update_security_group(self):
        _process_p_updata_sg = ('midonet.neutron.db.regional_securitygroup_db.'
                                'RegionalSecurityGroupDbMixin.'
                                '_process_port_update_security_group')
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    ctxt = ncontext.get_admin_context()
                    orig_port = port['port']
                    id = orig_port['id']
                    updated_port = copy.deepcopy(orig_port)
                    p = {'port': {'security_groups': []}}
                    with mock.patch(_process_p_updata_sg) as process_update:
                        process_update.return_value = None
                        self.plugin.update_security_group_on_port(ctxt, id, p,
                                                                  orig_port,
                                                                  updated_port)
                        self.assertEqual(1, process_update.call_count)

    def test_update_security_group_on_port_update_ip(self):
        _process_p_updata_sg = ('midonet.neutron.db.regional_securitygroup_db.'
                                'RegionalSecurityGroupDbMixin.'
                                '_process_port_update_security_group')
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    ctxt = ncontext.get_admin_context()
                    orig_port = port['port']
                    id = orig_port['id']
                    updated_port = copy.deepcopy(orig_port)
                    updated_port['fixed_ips'].append({'ip_address':
                                                      '10.0.0.100'})
                    p = {'port': {'name': 'dummy'}}
                    with mock.patch(_process_p_updata_sg) as process_update:
                        process_update.return_value = None
                        self.plugin.update_security_group_on_port(ctxt, id, p,
                                                                  orig_port,
                                                                  updated_port)
                        self.assertEqual(1, process_update.call_count)

    def test_update_security_group_on_port_no_update(self):
        _process_p_updata_sg = ('midonet.neutron.db.regional_securitygroup_db.'
                                'RegionalSecurityGroupDbMixin.'
                                '_process_port_update_security_group')
        with self.network() as net, self.subnet(net) as sub:
            with self.security_group('webservers', 'webservers') as sg:
                sgid = sg['security_group']['id']
                with self.port(subnet=sub, security_groups=[sgid]) as port:
                    ctxt = ncontext.get_admin_context()
                    orig_port = port['port']
                    id = orig_port['id']
                    updated_port = copy.deepcopy(orig_port)
                    p = {'port': {'name': 'dummy'}}
                    with mock.patch(_process_p_updata_sg) as process_update:
                        process_update.return_value = None
                        self.plugin.update_security_group_on_port(ctxt, id, p,
                                                                  orig_port,
                                                                  updated_port)
                        self.assertEqual(0, process_update.call_count)

    def test_notify_created_security_group_confict(self):
        ctxt = ncontext.Context('', 'somebody')
        body1 = {'security_group': {'name': 'webservers',
                                   'description': 'webservers'}}
        sg1 = sgc_mock.create_security_group_without_notify(ctxt, body1)
        body2 = {'security_group': {'name': 'webservers',
                                   'description': 'webservers'}}
        sg2 = sgc_mock.create_security_group_without_notify(ctxt, body2)
        sgids = [sg1['id'], sg2['id']]
        sgs = [sg1, sg2]
        create_sg = self.client_mock.create_security_group_postcommit
        create_sg.side_effect = webob.exc.HTTPConflict
        with mock.patch.object(self.plugin, 'get_security_groups') as get_sgs:
            get_sgs.return_value = sgs
            res = self.plugin._notify_created_security_group(ctxt, sgids)
            self.assertEqual(sgids, res)
            self.assertEqual(2, create_sg.call_count)

    def test_notify_created_security_group_http_error(self):
        ctxt = ncontext.Context('', 'somebody')
        body1 = {'security_group': {'name': 'webservers',
                                   'description': 'webservers'}}
        sg1 = sgc_mock.create_security_group_without_notify(ctxt, body1)
        body2 = {'security_group': {'name': 'webservers',
                                   'description': 'webservers'}}
        sg2 = sgc_mock.create_security_group_without_notify(ctxt, body2)
        sgids = [sg1['id'], sg2['id']]
        sgs = [sg1, sg2]
        create_sg = self.client_mock.create_security_group_postcommit
        create_sg.side_effect = webob.exc.HTTPError
        with mock.patch.object(self.plugin, 'get_security_groups') as get_sgs:
            get_sgs.return_value = sgs
            self.assertRaises(webob.exc.HTTPError,
                              self.plugin._notify_created_security_group,
                              ctxt, sgids)
            self.assertEqual(1, create_sg.call_count)

    def test_notify_deleted_security_group_not_found(self):
        ctxt = ncontext.get_admin_context()
        ids = ['dummy1', 'dummy2']
        delete_sg = self.client_mock.delete_security_group_postcommit
        delete_sg.side_effect = webob.exc.HTTPNotFound
        res = self.plugin._notify_deleted_security_group(ctxt, ids)
        self.assertIsNone(res)
        self.assertEqual(2, delete_sg.call_count)

    def test_notify_deleted_security_group_http_error(self):
        ctxt = ncontext.get_admin_context()
        ids = ['dummy1', 'dummy2']
        delete_sg = self.client_mock.delete_security_group_postcommit
        delete_sg.side_effect = webob.exc.HTTPError
        res = self.plugin._notify_deleted_security_group(ctxt, ids)
        self.assertIsNone(res)
        self.assertEqual(2, delete_sg.call_count)

    def test_notify_created_security_group_rule_conflict(self):
        with self.security_group('webservers', 'webservers') as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            ctxt = ncontext.Context('', tenant_id)
            body1 = {'security_group_rule': {'security_group_id': sg_id,
                                             'protocol': 'TCP',
                                             'direction': "ingress",
                                             'ethertype': 'ipv4',
                                             'port_range_min': None,
                                             'port_range_max': None,
                                             'remote_ip_prefix': None,
                                             'remote_group_id': None,
                                             'tenant_id': tenant_id
                                             }}
            sgr1 = sgc_mock.create_security_group_rule_without_notify(ctxt,
                                                                      body1)
            body2 = copy.deepcopy(body1)
            body2['security_group_rule']['direction'] = 'egress'
            sgr2 = sgc_mock.create_security_group_rule_without_notify(ctxt,
                                                                      body2)
            rule_ids = [sgr1['id'], sgr2['id']]
            rules = [sgr1, sgr2]
            create_sgr = self.client_mock.create_security_group_rule_postcommit
            create_sgr.side_effect = webob.exc.HTTPConflict
            with mock.patch.object(self.plugin,
                                   'get_security_group_rules') as get_sg_rules:
                get_sg_rules.return_value = rules
                res = self.plugin._notify_created_security_group_rule(
                                                                ctxt, rule_ids)
                self.assertEqual(rule_ids, res)
                self.assertEqual(2, create_sgr.call_count)

    def test_notify_created_security_group_rule_http_error(self):
        with self.security_group('webservers', 'webservers') as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            ctxt = ncontext.Context('', tenant_id)
            body1 = {'security_group_rule': {'security_group_id': sg_id,
                                             'protocol': 'TCP',
                                             'direction': "ingress",
                                             'ethertype': 'ipv4',
                                             'port_range_min': None,
                                             'port_range_max': None,
                                             'remote_ip_prefix': None,
                                             'remote_group_id': None,
                                             'tenant_id': tenant_id
                                             }}
            sgr1 = sgc_mock.create_security_group_rule_without_notify(ctxt,
                                                                      body1)
            body2 = copy.deepcopy(body1)
            body2['security_group_rule']['direction'] = 'egress'
            sgr2 = sgc_mock.create_security_group_rule_without_notify(ctxt,
                                                                      body2)
            rule_ids = [sgr1['id'], sgr2['id']]
            rules = [sgr1, sgr2]
            create_sgr = self.client_mock.create_security_group_rule_postcommit
            create_sgr.side_effect = webob.exc.HTTPError
            with mock.patch.object(self.plugin,
                                   'get_security_group_rules') as get_sg_rules:
                get_sg_rules.return_value = rules
                self.assertRaises(
                            webob.exc.HTTPError,
                            self.plugin._notify_created_security_group_rule,
                            ctxt, rule_ids)
                self.assertEqual(1, create_sgr.call_count)

    def test_notify_deleted_security_group_rule_not_found(self):
        ctxt = ncontext.get_admin_context()
        ids = ['dummy1', 'dummy2']
        delete_sgr = self.client_mock.delete_security_group_rule_postcommit
        delete_sgr.side_effect = webob.exc.HTTPNotFound
        res = self.plugin._notify_deleted_security_group_rule(ctxt, ids)
        self.assertIsNone(res)
        self.assertEqual(2, delete_sgr.call_count)

    def test_notify_deleted_security_group_rule_http_error(self):
        ctxt = ncontext.get_admin_context()
        ids = ['dummy1', 'dummy2']
        delete_sgr = self.client_mock.delete_security_group_rule_postcommit
        delete_sgr.side_effect = webob.exc.HTTPError
        res = self.plugin._notify_deleted_security_group_rule(ctxt, ids)
        self.assertIsNone(res)
        self.assertEqual(2, delete_sgr.call_count)

    def test_notify_created_security_group_member_conflict(self):
        ctxt = ncontext.get_admin_context()
        sgid = 'dummy'
        ips = ['10.0.0.4', '10.0.1.5']
        create_ipaddr = self.client_mock.create_ipaddr_group_addr
        create_ipaddr.side_effect = webob.exc.HTTPConflict
        res = self.plugin._notify_created_security_group_member(ctxt,
                                                                sgid, ips)
        self.assertIsNone(res)
        self.assertEqual(2, create_ipaddr.call_count)

    def test_notify_created_security_group_member_http_error(self):
        ctxt = ncontext.get_admin_context()
        sgid = 'dummy'
        ips = ['10.0.0.4', '10.0.1.5']
        create_ipaddr = self.client_mock.create_ipaddr_group_addr
        create_ipaddr.side_effect = webob.exc.HTTPError
        self.assertRaises(webob.exc.HTTPError,
                          self.plugin._notify_created_security_group_member,
                          ctxt, sgid, ips)
        self.assertEqual(1, create_ipaddr.call_count)

    def test_notify_deleted_security_group_member_not_found(self):
        ctxt = ncontext.get_admin_context()
        sgid = 'dummy'
        ips = ['10.0.0.4', '10.0.1.5']
        delete_ipaddr = self.client_mock.delete_ipaddr_group_addr
        delete_ipaddr.side_effect = webob.exc.HTTPNotFound
        res = self.plugin._notify_deleted_security_group_member(ctxt,
                                                                sgid, ips)
        self.assertIsNone(res)
        self.assertEqual(2, delete_ipaddr.call_count)

    def test_notify_deleted_security_group_member_http_error(self):
        ctxt = ncontext.get_admin_context()
        sgid = 'dummy'
        ips = ['10.0.0.4', '10.0.1.5']
        delete_ipaddr = self.client_mock.delete_ipaddr_group_addr
        delete_ipaddr.side_effect = webob.exc.HTTPError
        res = self.plugin._notify_deleted_security_group_member(ctxt,
                                                                sgid, ips)
        self.assertIsNone(res)
        self.assertEqual(2, delete_ipaddr.call_count)

    def test_check_security_group_changes_with_creations(self):
        ctxt = ncontext.get_admin_context()
        change_ids = ['dummy1', 'dummy2']
        with mock.patch.object(self.plugin,
                               'get_security_groups_minimal') as get_minimal:
            get_minimal.return_value = [{'id': id} for id in change_ids]
            create_sgids, delete_sgids = (
                self.plugin._check_security_group_changes(ctxt, change_ids))
            self.assertEqual(set(change_ids), create_sgids)
            self.assertEqual(set([]), delete_sgids)

    def test_check_security_group_changes_with_deletesion(self):
        ctxt = ncontext.get_admin_context()
        change_ids = ['dummy1', 'dummy2']
        with mock.patch.object(self.plugin,
                               'get_security_groups_minimal') as get_minimal:
            get_minimal.return_value = []
            create_sgids, delete_sgids = (
                self.plugin._check_security_group_changes(ctxt, change_ids))
            self.assertEqual(set([]), create_sgids)
            self.assertEqual(set(change_ids), delete_sgids)

    def test_check_security_group_changes_with_both(self):
        ctxt = ncontext.get_admin_context()
        change_ids = ['dummy1', 'dummy2']
        with mock.patch.object(self.plugin,
                               'get_security_groups_minimal') as get_minimal:
            get_minimal.return_value = [{'id': change_ids[0]}]
            create_sgids, delete_sgids = (
                self.plugin._check_security_group_changes(ctxt, change_ids))
            self.assertEqual(set([change_ids[0]]), create_sgids)
            self.assertEqual(set([change_ids[1]]), delete_sgids)

    def test_check_security_group_rule_updated(self):
        with self.security_group('webservers', 'webservers') as sg1:
            with self.security_group('webservers2', 'webservers2') as sg2:
                ctxt = ncontext.get_admin_context()
                sgs = [sg1['security_group'], sg2['security_group']]
                ids = [sg['id'] for sg in sgs]
                expect = {sg['id']:
                          [rule['id'] for rule in sg['security_group_rules']]
                          for sg in sgs}
                sg_rule_map = (
                    self.plugin._check_security_group_rule_updated(ctxt, ids))
                self.assertEqual(expect, sg_rule_map)

    def test_make_mido_rule_map(self):
        with self.security_group('webservers', 'webservers'):
            with self.security_group('webservers2', 'webservers2'):
                ctxt = ncontext.get_admin_context()
                sgs = self.plugin.get_security_groups_minimal(ctxt)
                expect = {sg['id']: sg['security_group_rules'] for sg in sgs}
                mido_rule_map = self.plugin._make_mido_rule_map(ctxt)
                self.assertEqual(expect, mido_rule_map)

    def test_notify_security_group_rule_updated_no_updates(self):
        create_rule = '_notify_created_security_group_rule'
        delete_rule = '_notify_deleted_security_group_rule'
        with contextlib.nested(self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sg1, sg2):
            ctxt = ncontext.get_admin_context()
            sgs = [sg1['security_group'], sg2['security_group']]
            ids = [sg['id'] for sg in sgs]
            sg_rule_map = (
                self.plugin._check_security_group_rule_updated(ctxt, ids))
            mido_rule_map = self.plugin._make_mido_rule_map(ctxt)

            with contextlib.nested(mock.patch.object(self.plugin, create_rule),
                                   mock.patch.object(self.plugin, delete_rule)
                                   ) as (create_r, delete_r):
                res = self.plugin._notify_security_group_rule_updated(
                                            ctxt, sg_rule_map, mido_rule_map)
                self.assertIsNone(res)
                self.assertEqual(0, create_r.call_count)
                self.assertEqual(0, delete_r.call_count)

    def test_notify_security_group_rule_create_rules(self):
        create_rule = '_notify_created_security_group_rule'
        delete_rule = '_notify_deleted_security_group_rule'
        with contextlib.nested(self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sg1, sg2):
            ctxt = ncontext.get_admin_context()
            sgs = [sg1['security_group'], sg2['security_group']]
            ids = [sg['id'] for sg in sgs]
            sg_rule_map = (
                self.plugin._check_security_group_rule_updated(ctxt, ids))
            mido_rule_map = self.plugin._make_mido_rule_map(ctxt)

            with contextlib.nested(mock.patch.object(self.plugin, create_rule),
                                   mock.patch.object(self.plugin, delete_rule)
                                   ) as (create_r, delete_r):
                create_r.return_value = None
                sg_rule_map[ids[0]].append('dummy1')
                sg_rule_map[ids[1]].append('dummy2')
                res = self.plugin._notify_security_group_rule_updated(
                                            ctxt, sg_rule_map, mido_rule_map)
                self.assertIsNone(res)
                self.assertEqual(1, create_r.call_count)
                called_rules = create_r.call_args[0][1]
                self.assertIn('dummy1', called_rules)
                self.assertIn('dummy2', called_rules)
                self.assertEqual(0, delete_r.call_count)

    def test_notify_security_group_rule_delete_rules(self):
        create_rule = '_notify_created_security_group_rule'
        delete_rule = '_notify_deleted_security_group_rule'
        with contextlib.nested(self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sg1, sg2):
            ctxt = ncontext.get_admin_context()
            sgs = [sg1['security_group'], sg2['security_group']]
            ids = [sg['id'] for sg in sgs]
            sg_rule_map = (
                self.plugin._check_security_group_rule_updated(ctxt, ids))
            mido_rule_map = self.plugin._make_mido_rule_map(ctxt)

            with contextlib.nested(mock.patch.object(self.plugin, create_rule),
                                   mock.patch.object(self.plugin, delete_rule)
                                   ) as (create_r, delete_r):
                delete_r.return_value = None
                mido_rule_map[ids[0]].append('dummy1')
                mido_rule_map[ids[1]].append('dummy2')
                res = self.plugin._notify_security_group_rule_updated(
                                            ctxt, sg_rule_map, mido_rule_map)
                self.assertIsNone(res)
                self.assertEqual(0, create_r.call_count)
                self.assertEqual(1, delete_r.call_count)
                called_rules = delete_r.call_args[0][1]
                self.assertIn('dummy1', called_rules)
                self.assertIn('dummy2', called_rules)

    def test_notify_security_group_member_updated_no_updates(self):
        create_member = '_notify_created_security_group_member'
        delete_member = '_notify_deleted_security_group_member'
        with contextlib.nested(self.subnet(),
                               self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sub, sg1, sg2):
            sgs = [sg1['security_group'], sg2['security_group']]
            sgids = [sg['id'] for sg in sgs]
            ctxt = ncontext.get_admin_context()

            with contextlib.nested(self.port(subnet=sub,
                                             security_groups=[sgids[0]]),
                                   self.port(subnet=sub,
                                             security_groups=[sgids[1]])):
                sg_ip_map = self.plugin._make_sg_ip_map(ctxt, sgids)

                with contextlib.nested(mock.patch.object(self.plugin,
                                                         create_member),
                                       mock.patch.object(self.plugin,
                                                         delete_member)
                                       ) as (create_m, delete_m):
                    self.plugin._notify_security_group_member_updated(
                                                            ctxt, sg_ip_map)
                    self.assertEqual(0, create_m.call_count)
                    self.assertEqual(0, delete_m.call_count)

    def test_notify_security_group_member_updated_create_members(self):
        create_member = '_notify_created_security_group_member'
        delete_member = '_notify_deleted_security_group_member'
        with contextlib.nested(self.subnet(),
                               self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sub, sg1, sg2):
            sgs = [sg1['security_group'], sg2['security_group']]
            sgids = [sg['id'] for sg in sgs]
            ctxt = ncontext.get_admin_context()

            with contextlib.nested(self.port(subnet=sub,
                                             security_groups=[sgids[0]]),
                                   self.port(subnet=sub,
                                             security_groups=[sgids[1]])):
                sg_ip_map = self.plugin._make_sg_ip_map(ctxt, sgids)

                with contextlib.nested(mock.patch.object(self.plugin,
                                                         create_member),
                                       mock.patch.object(self.plugin,
                                                         delete_member)
                                       ) as (create_m, delete_m):
                    create_m.return_value = None
                    add_ips = ['10.0.0.100', '10.0.0.200']
                    sg_ip_map[sgids[0]].append(add_ips[0])
                    sg_ip_map[sgids[1]].append(add_ips[1])
                    self.plugin._notify_security_group_member_updated(
                                                            ctxt, sg_ip_map)
                    self.assertEqual(2, create_m.call_count)
                    self.assertEqual(0, delete_m.call_count)
                    for called in create_m.call_args_list:
                        for i in range(len(sgids)):
                            if sgids[i] in called:
                                self.assertIn(add_ips[i], called[2])

    def test_notify_security_group_member_updated_delete_members(self):
        create_member = '_notify_created_security_group_member'
        delete_member = '_notify_deleted_security_group_member'
        with contextlib.nested(self.subnet(),
                               self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')
                               ) as (sub, sg1, sg2):
            sgs = [sg1['security_group'], sg2['security_group']]
            sgids = [sg['id'] for sg in sgs]
            ctxt = ncontext.get_admin_context()

            with contextlib.nested(self.port(subnet=sub,
                                             security_groups=[sgids[0]]),
                                   self.port(subnet=sub,
                                             security_groups=[sgids[1]])):
                sg_ip_map = self.plugin._make_sg_ip_map(ctxt, sgids)

                with contextlib.nested(mock.patch.object(self.plugin,
                                                         create_member),
                                       mock.patch.object(self.plugin,
                                                         delete_member)
                                       ) as (create_m, delete_m):
                    delete_m.return_value = None
                    remove_ips = [sg_ip_map[id] for id in sgids]
                    sg_ip_map[sgids[0]] = []
                    sg_ip_map[sgids[1]] = []
                    self.plugin._notify_security_group_member_updated(
                                                            ctxt, sg_ip_map)
                    self.assertEqual(0, create_m.call_count)
                    self.assertEqual(2, delete_m.call_count)
                    for called in delete_m.call_args_list:
                        for i in range(len(sgids)):
                            if sgids[i] in called:
                                self.assertIn(remove_ips[i], called[2])

    def test_sync_sg_service(self):
        get_sg_mini = 'get_security_groups_minimal'
        with contextlib.nested(self.security_group('webservers',
                                                   'webservers'),
                               self.security_group('webservers2',
                                                   'webservers2')):
            # check sync_sg_service in normal condition
            self.plugin.sync_sg_service()

            # check sync_sg_service with exception
            with mock.patch.object(self.plugin, get_sg_mini) as get_sg:
                get_sg.side_effect = webob.exc.HTTPServiceUnavailable
                # check if sync_sg_service catches the exception
                self.plugin.sync_sg_service()
                self.assertEqual(1, get_sg.call_count)
