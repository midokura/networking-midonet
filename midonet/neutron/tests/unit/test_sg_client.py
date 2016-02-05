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
import mock
import requests
import webob.exc as wexc

from midonet.neutron.client import sg_client

from neutron.common import exceptions as n_exc
from neutron import context as ncontext
from neutron.extensions import securitygroup
from neutron.tests import base

from oslo_config import cfg
from oslo_serialization import jsonutils

SG_INFO = {
    'tenant_id': '3a7c9539cf224a51972a5ef40a4377a2',
    'name': 'test',
    'description': '',
    'security_group_rules':
    [
        {
            'id': '64be04cc-3e2d-40a0-91b7-6a49246cda3d',
            'direction': 'egress', 'protocol': None,
            'ethertype': 'IPv4',
            'port_range_min': None, 'port_range_max': None,
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'tenant_id': '3a7c9539cf224a51972a5ef40a4377a2',
            'security_group_id': '5c6d1ec1-fb42-4ed2-8cc5-5a6f63285bd0',
        },
        {
            'id': 'dd8ff4b2-99fe-4e25-8c24-64d3cacd58de',
            'direction': 'egress', 'protocol': None,
            'ethertype': 'IPv6',
            'port_range_min': None, 'port_range_max': None,
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'tenant_id': '3a7c9539cf224a51972a5ef40a4377a2',
            'security_group_id': '5c6d1ec1-fb42-4ed2-8cc5-5a6f63285bd0',
        }
    ],
    'id': '5c6d1ec1-fb42-4ed2-8cc5-5a6f63285bd0'}

SECURITY_GROUP = {'security_group': SG_INFO}
SECURITY_GROUPS = {'security_groups': [SG_INFO]}

RULE_INFO = {
    "id": "9b4a066b-faa0-4ec3-85f8-f165d56f5af9",
    "direction": "ingress",
    "protocol": "tcp",
    "ethertype": "IPv4",
    "port_range_min": 22,
    "port_range_max": 22,
    "remote_group_id": None,
    "remote_ip_prefix": None,
    "tenant_id": "3a7c9539cf224a51972a5ef40a4377a2",
    "security_group_id": "5c6d1ec1-fb42-4ed2-8cc5-5a6f63285bd0"}

SG_RULE = {'security_group_rule': RULE_INFO}
SG_RULES = {'security_group_rules': [RULE_INFO]}

PBIND_INFO = {
    "id": "650cc98e-2afd-41fe-8a2f-73e344d3adf2",
    "ips":
        [
            "10.0.0.3",
            "10.0.0.4"
        ],
    "security_groups": [SG_INFO],
    "tenant_id": "3a7c9539cf224a51972a5ef40a4377a2"}

PBINDING = {"portbinding": PBIND_INFO}
PBINDINGS = {"portbindings": [PBIND_INFO]}

# HTTP ERROR codes([400, 403, 404, 409, 503] and 500)
ERROR_CODES = sorted(sg_client.fault_map)
INTERNAL_SERVER_ERROR = wexc.HTTPInternalServerError.code


class SGClientTestCase(base.BaseTestCase):
    def setUp(self):
        sg_url = 'https://172.16.1.11:9696/internal/v2.0'
        cfg.CONF.set_override('sg_url', sg_url)
        cfg.CONF.set_override('sg_http_timeout', '60')
        cfg.CONF.set_override('sg_verify_ssl', False)
        super(SGClientTestCase, self).setUp()
        use_fatal_exce_mock = mock.patch('neutron.common.exceptions.'
                                         'NeutronException.'
                                         'use_fatal_exceptions')
        use_fatal_exce_mock.start().return_value = False

    def tearDown(self):
        super(SGClientTestCase, self).tearDown()

    def set_context(self, admin=False):
        if admin:
            context = ncontext.get_admin_context()
        else:
            user_id = '515ef0718d854fdb87574d1f8eec39af'
            tenant_id = '3a7c9539cf224a51972a5ef40a4377a2'
            context = ncontext.Context(user_id, tenant_id)
        return context

    def set_mock_response(self, status_code, body=None):
        if not body:
            body = {}
        mock_res = requests.Response()
        mock_res.status_code = status_code
        content = jsonutils.dumps(body)
        mock_res._content = content
        return mock_res


class TestDoRequest(SGClientTestCase):
    @mock.patch('requests.request')
    def test_do_request_http_ok(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SECURITY_GROUPS)
        res = sg_client.do_request(context, 'GET', 'security-groups')
        self.assertEqual(SECURITY_GROUPS, res)

    @mock.patch('requests.request')
    def test_do_request_http_created(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_CREATED,
                                                        body=SECURITY_GROUP)
        body = {'security_group': {'name': 'test'}}
        res = sg_client.do_request(context, 'POST',
                                   'security-groups', body=body)
        self.assertEqual(SECURITY_GROUP, res)

    @mock.patch('requests.request')
    def test_do_request_http_no_content(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(
                                                    sg_client.HTTP_NO_CONTENT)
        id = SG_INFO['id']
        res = sg_client.do_request(context, 'DELETE',
                                   "security-groups", resource_id=id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_do_request_neutron_err(self, m_request):
        context = self.set_context()
        id = SG_INFO['id']
        sg_not_found = securitygroup.SecurityGroupNotFound(id=SG_INFO['id'])
        message = {"NeutronError": {"message": sg_not_found.msg,
                                    "type": "SecurityGroupNotFound",
                                    "detail": ""}}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        self.assertRaises(securitygroup.SecurityGroupNotFound,
                          sg_client.do_request,
                          context, 'GET', 'security-groups',
                          resource_id=id)

    @mock.patch('requests.request')
    def test_do_request_bad_request(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(ERROR_CODES[0])
        body = {}
        self.assertRaises(wexc.HTTPBadRequest, sg_client.do_request,
                          context, 'POST', 'security-groups', body=body)

    @mock.patch('requests.request')
    def test_do_request_forbidden(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(ERROR_CODES[1])
        self.assertRaises(wexc.HTTPForbidden, sg_client.do_request,
                          context, 'GET', 'security_group')

    @mock.patch('requests.request')
    def test_do_request_not_found(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(ERROR_CODES[2])
        id = SG_INFO['id']
        self.assertRaises(wexc.HTTPNotFound, sg_client.do_request,
                          context, 'DELETE', 'security_group',
                          resource_id=id)

    @mock.patch('requests.request')
    def test_do_request_conflict(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(ERROR_CODES[3])
        id = SG_INFO['id']
        self.assertRaises(wexc.HTTPConflict, sg_client.do_request,
                          context, 'PUT', 'security_group', resource_id=id)

    @mock.patch('requests.request')
    def test_do_request_service_unavailable(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(ERROR_CODES[4])
        self.assertRaises(wexc.HTTPServiceUnavailable,
                          sg_client.do_request,
                          context, 'GET', 'security_group')

    @mock.patch('requests.request')
    def test_do_request_internal_server_error(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(INTERNAL_SERVER_ERROR)
        self.assertRaises(sg_client.SGClientException, sg_client.do_request,
                          context, 'GET', 'security_group')


class TestSGClient(SGClientTestCase):
    """This tests sg client.
    """

    @mock.patch('requests.request')
    def test_create_security_group(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_CREATED,
                                                        body=SECURITY_GROUP)
        security_group = {'security_group': {'name': 'test'}}
        res = sg_client.create_security_group(context, security_group)
        self.assertEqual(SG_INFO, res)

    @mock.patch('requests.request')
    def test_update_security_group(self, m_request):
        context = self.set_context()
        update_sg_info = SG_INFO.copy()
        update_sg_info['name'] = 'update_test'
        update_sg = {'security_group': update_sg_info}
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=update_sg)
        id = SG_INFO['id']
        security_group = {'security_group': {'name': 'update_test'}}
        res = sg_client.update_security_group(context, id, security_group)
        self.assertEqual(update_sg_info, res)

    @mock.patch('requests.request')
    def test_delete_security_group(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(
                                                    sg_client.HTTP_NO_CONTENT)
        id = SG_INFO['id']
        res = sg_client.delete_security_group(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_security_group_ignore_http_not_found(self, m_request):
        context = self.set_context()
        message = {"message": "Dummy Resource Not Found."}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        id = SG_INFO['id']
        res = sg_client.delete_security_group(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_security_group_ignore_sg_not_found(self, m_request):
        context = self.set_context()
        id = SG_INFO['id']
        sg_not_found = securitygroup.SecurityGroupNotFound(id=id)
        message = {"NeutronError": {"message": sg_not_found.msg,
                                    "type": "SecurityGroupNotFound",
                                    "detail": ""}}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        res = sg_client.delete_security_group(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_get_security_groups(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SECURITY_GROUPS)
        res = sg_client.get_security_groups(context)
        self.assertEqual([SG_INFO], res)

    @mock.patch('requests.request')
    def test_get_security_groups_with_filters(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SECURITY_GROUPS)
        filters = {'id': [SG_INFO['id']]}
        res = sg_client.get_security_groups(context, filters=filters)
        self.assertEqual([SG_INFO], res)

    @mock.patch('requests.request')
    def test_get_security_group(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SECURITY_GROUP)
        id = SG_INFO['id']
        res = sg_client.get_security_group(context, id)
        self.assertEqual(SG_INFO, res)

    @mock.patch('requests.request')
    def test_create_security_group_rule(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_CREATED,
                                                        body=SG_RULE)
        sg_rule = {"security_group_rule": {"direction": "ingress",
                                           "port_range_min": "22",
                                           "ethertype": "IPv4",
                                           "port_range_max": "22",
                                           "protocol": "tcp",
                                           "security_group_id": SG_INFO['id']}}
        res = sg_client.create_security_group_rule(context, sg_rule)
        self.assertEqual(RULE_INFO, res)

    @mock.patch('requests.request')
    def test_delete_security_group_rule(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(
                                                    sg_client.HTTP_NO_CONTENT)
        id = RULE_INFO['id']
        res = sg_client.delete_security_group_rule(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_security_group_rule_ignore_http_not_found(self, m_request):
        context = self.set_context()
        message = {"message": "Dummy Resource Not Found."}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        id = RULE_INFO['id']
        res = sg_client.delete_security_group_rule(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_security_group_rule_ignore_sgr_not_found(self, m_request):
        context = self.set_context()
        id = RULE_INFO['id']
        sgr_not_found = securitygroup.SecurityGroupRuleNotFound(id=id)
        message = {"NeutronError": {"message": sgr_not_found.msg,
                                    "type": "SecurityGroupRuleNotFound",
                                    "detail": ""}}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        res = sg_client.delete_security_group_rule(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_get_security_group_rules(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SG_RULES)
        res = sg_client.get_security_group_rules(context)
        self.assertEqual([RULE_INFO], res)

    @mock.patch('requests.request')
    def test_get_security_group_rule(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SG_RULE)
        id = RULE_INFO['id']
        res = sg_client.get_security_group_rule(context, id)
        self.assertEqual(RULE_INFO, res)

    @mock.patch('requests.request')
    def test_create_portbinding(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_CREATED,
                                                        body=PBINDING)
        pb = {'portbinding': {'id': PBIND_INFO['id'],
                              'ips': ['10.0.0.3', '10.0.0.4'],
                              'security_groups': [SG_INFO['id']]}}
        res = sg_client.create_portbinding(context, pb)
        self.assertEqual(PBIND_INFO, res)

    @mock.patch('requests.request')
    def test_update_portbinding(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=PBINDING)
        id = PBIND_INFO['id']
        pb = {'portbinding': {'id': PBIND_INFO['id'],
                              'ips': ['10.0.0.3', '10.0.0.4'],
                              'security_groups': [SG_INFO['id']]}}
        res = sg_client.update_portbinding(context, id, pb)
        self.assertEqual(PBIND_INFO, res)

    @mock.patch('requests.request')
    def test_delete_portbinding(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(
                                                    sg_client.HTTP_NO_CONTENT)
        id = PBIND_INFO['id']
        res = sg_client.delete_portbinding(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_portbinding_ignore_http_not_found(self, m_request):
        context = self.set_context()
        message = {"message": "Dummy Resource Not Found."}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        id = PBIND_INFO['id']
        res = sg_client.delete_portbinding(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_delete_portbinding_ignore_sg_not_found(self, m_request):
        context = self.set_context()
        p_not_found = n_exc.PortNotFound(port_id=PBIND_INFO['id'])
        message = {"NeutronError": {"message": p_not_found.msg,
                                    "type": "PortNotFound",
                                    "detail": ""}}
        m_request.return_value = self.set_mock_response(ERROR_CODES[2],
                                                        body=message)
        id = PBIND_INFO['id']
        res = sg_client.delete_portbinding(context, id)
        self.assertIsNone(res)

    @mock.patch('requests.request')
    def test_get_portbindings(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=PBINDINGS)
        res = sg_client.get_portbindings(context)
        self.assertEqual([PBIND_INFO], res)

    @mock.patch('requests.request')
    def test_get_portbindings_with_port_ids(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=PBINDINGS)
        port_ids = [PBIND_INFO['id']]
        res = sg_client.get_portbindings(context, port_ids=port_ids)
        self.assertEqual([PBIND_INFO], res)

    @mock.patch('requests.request')
    def test_get_portbinding(self, m_request):
        context = self.set_context()
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=PBINDING)
        id = PBIND_INFO['id']
        res = sg_client.get_portbinding(context, id)
        self.assertEqual(PBIND_INFO, res)

    @mock.patch('requests.request')
    def test_get_security_groups_by_ids(self, m_request):
        context = self.set_context(admin=True)
        m_request.return_value = self.set_mock_response(sg_client.HTTP_OK,
                                                        body=SECURITY_GROUPS)
        ids = [PBIND_INFO['id']]
        res = sg_client.get_security_groups_by_ids(context, ids)
        self.assertEqual([SG_INFO], res)
