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

from midonet.neutron.tests.unit import test_midonet_plugin_v2 as test_mn

from neutron.db import servicetype_db as sdb
from neutron import extensions as nextensions
from neutron.plugins.common import constants as n_const
from neutron.tests.unit.api import test_extensions as test_ex
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron_vpnaas import extensions
from neutron_vpnaas.tests.unit.db.vpn import test_vpn_db

from oslo_config import cfg

MN_DRIVER_KLASS = ('midonet.neutron.services.vpn.service_drivers.'
                   'midonet_ipsec.MidonetIPsecVPNDriver')

extensions_path = ':'.join(extensions.__path__ + nextensions.__path__)
DB_VPN_PLUGIN_KLASS = "neutron_vpnaas.services.vpn.plugin.VPNDriverPlugin"


class VPNTestExtensionManager(test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(VPNTestExtensionManager, self).get_resources()
        return res + extensions.vpnaas.Vpnaas.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class VPNTestCase(test_vpn_db.VPNTestMixin,
                  test_l3_plugin.L3NatTestCaseMixin,
                  test_mn.MidonetPluginV2TestCase):
    def setUp(self):
        service_plugins = {
            'vpnaas_plugin': DB_VPN_PLUGIN_KLASS}
        vpnaas_provider = (n_const.VPN + ':vpnaas:' + MN_DRIVER_KLASS
                           + ':default')
        ext_mgr = VPNTestExtensionManager()
        cfg.CONF.set_override('service_provider',
                              [vpnaas_provider],
                              'service_providers')
        sdb.ServiceTypeManager._instance = None

        super(VPNTestCase, self).setUp(service_plugins=service_plugins,
                                       ext_mgr=ext_mgr)
        self.ext_api = test_ex.setup_extensions_middleware(ext_mgr)

    def test_update_vpn_service(self):
        with self.vpnservice() as vpnservice:
            data = {'vpnservice': {'name': 'vpnservice2'}}
            vpnservice_id = vpnservice['vpnservice']['id']
            req = self.new_update_request('vpnservices', data, vpnservice_id)
            res = req.get_response(self.ext_api)
            # Note: Neutron doesn't allow updating vpnservice in PENDING_CREATE
            # which is set to ACTIVE only when we create the ipsec site conn
            self.assertEqual(400, res.status_int)

    def test_update_vpn_service_after_ipsec_conn_create(self):
        with self.vpnservice() as vpnservice, \
            self.ipsec_site_connection(vpnservice=vpnservice):
            data = {'vpnservice': {'name': 'vpnservice2'}}
            vpnservice_id = vpnservice['vpnservice']['id']
            req = self.new_update_request('vpnservices', data, vpnservice_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(n_const.ACTIVE, res['vpnservice']['status'])
            self.assertEqual('vpnservice2', res['vpnservice']['name'])
            self.assertEqual(
                'vpnservice2',
                self.client_mock.update_vpn_service.call_args[0][2]['name'])

    def test_update_vpn_service_error_change_neutron_resource_status(self):
        self.client_mock.update_vpn_service.side_effect = Exception(
            "Fake Error")
        with self.vpnservice() as vpnservice, \
            self.ipsec_site_connection(vpnservice=vpnservice):
            data = {'vpnservice': {'name': 'vpnservice2'}}
            vpnservice_id = vpnservice['vpnservice']['id']
            req = self.new_update_request('vpnservices', data, vpnservice_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(500, res.status_int)

            req = self.new_show_request('vpnservices', vpnservice_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(n_const.ERROR, res['vpnservice']['status'])

    def test_delete_vpnservice(self):
        """Test case to delete a vpnservice."""
        with self.vpnservice(name='vpnserver',
                             do_delete=False) as vpnservice:
            req = self.new_delete_request('vpnservices',
                                          vpnservice['vpnservice']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)

    def test_delete_vpnservice_error_delete_neutron_resouce(self):
        self.client_mock.delete_vpn_service_side_effect = Exception(
                "Fake Error")
        self.test_delete_vpnservice()
        # check the resouce deleted in Neutron DB
        req = self.new_list_request('vpnservices')
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertFalse(res['vpnservices'])

    def _create_ipsec_connection_on_success(self, vpnservice, ikepolicy,
                                            ipsecpolicy):
        with self.ipsec_site_connection(
                vpnservice=vpnservice,
                ikepolicy=ikepolicy, ipsecpolicy=ipsecpolicy) as site:
            ipsec_conn_id = site['ipsec_site_connection']['id']
            req = self.new_show_request('ipsec-site-connections',
                                        ipsec_conn_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            # Check status is ACTIVE
            self.assertEqual(n_const.ACTIVE,
                             res['ipsec_site_connection']['status'])
            # Check it's really created on the DB
            req = self.new_list_request('ipsec-site-connections')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertTrue(res['ipsec_site_connections'])
            # Check vpnservice status is ACTIVE
            req = self.new_show_request(
                'vpnservices',
                res['ipsec_site_connections'][0]['vpnservice_id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(n_const.ACTIVE,
                             res['vpnservice']['status'])
            args = self.client_mock.create_ipsec_site_conn.call_args[0][1]
            self.assertEqual(['10.0.0.0/24'], args['local_cidrs'])

    def test_create_ipsec_site_connection(self):
        with self.vpnservice() as vpnservice, \
                self.ikepolicy() as ikepolicy, \
                self.ipsecpolicy() as ipsecpolicy:
            self._create_ipsec_connection_on_success(vpnservice, ikepolicy,
                                                 ipsecpolicy)

    def _create_ipsec_connection_on_error(self, vpnservice, ikepolicy,
                                          ipsecpolicy, vpnservice_status):
        self._create_ipsec_site_connection(self.fmt, 'site_conn2',
                peer_cidrs='192.168.101.0/24',
                vpnservice_id=vpnservice['vpnservice']['id'],
                ikepolicy_id=ikepolicy['ikepolicy']['id'],
                ipsecpolicy_id=ipsecpolicy['ipsecpolicy']['id'],
                expected_res_status=500)
        # Check no objects are created
        req = self.new_list_request('ipsec-site-connections')
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertFalse(res['ipsec_site_connections'])
        # Check vpnservice went to a specific status
        req = self.new_show_request(
            'vpnservices', vpnservice['vpnservice']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(vpnservice_status,
                         res['vpnservice']['status'])

    def test_create_two_ipsec_site_connections_one_vpnservice(self):
        with self.vpnservice() as vpnservice, \
                self.ipsec_site_connection(vpnservice=vpnservice), \
                self.ipsec_site_connection(vpnservice=vpnservice,
                                           peer_address='192.168.1.11',
                                           peer_id='192.168.1.11',
                                           peer_cidrs=['10.0.11.0/24']):
            # Check there are two ipsec site connections
            req = self.new_list_request('ipsec-site-connections')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertTrue(len(res['ipsec_site_connections']) == 2)
            self.assertNotEqual(res['ipsec_site_connections'][0]['id'],
                                res['ipsec_site_connections'][1]['id'])

            for ipsec_site_connection in res['ipsec_site_connections']:
                # Check that the associated vpnservice is the correct one
                req = self.new_show_request(
                        'vpnservices', ipsec_site_connection['vpnservice_id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(vpnservice['vpnservice']['id'],
                                 res['vpnservice']['id'])

                self.assertEqual(n_const.ACTIVE,
                                 ipsec_site_connection['status'])

    def test_create_ipsec_site_connection_error_delete_neutron_resouce(self):
        with self.vpnservice() as vpnservice, \
                self.ikepolicy() as ikepolicy, \
                self.ipsecpolicy() as ipsecpolicy:
            self.client_mock.create_ipsec_site_conn.side_effect = Exception(
                "Fake Error on create_ipsec_site_connection")
            self._create_ipsec_connection_on_error(vpnservice, ikepolicy,
                                                   ipsecpolicy, n_const.ACTIVE)

    def test_create_ipsec_site_connection_on_vpnservice_error(self):
        with self.vpnservice() as vpnservice, \
                self.ikepolicy() as ikepolicy, \
                self.ipsecpolicy() as ipsecpolicy:
            self.client_mock.create_vpn_service.side_effect = Exception(
                "Fake Error on create_vpn_service")
            self._create_ipsec_connection_on_error(vpnservice, ikepolicy,
                                                   ipsecpolicy, n_const.ERROR)

    def test_update_ipsec_site_connection(self):
        with self.ipsec_site_connection() as ipsec_site_connection:
            data = {'ipsec_site_connection':
                {'mtu': '1300',
                 'peer_cidrs': ['30.0.0.0/24', '31.0.0.0/24'],
                 'dpd': {'interval': 45}}}

            ipsec_site_conn_id = (
                   ipsec_site_connection['ipsec_site_connection']['id'])
            req = self.new_update_request('ipsec-site-connections', data,
                    ipsec_site_conn_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(n_const.ACTIVE,
                    res['ipsec_site_connection']['status'])
            self.assertEqual(1300, res['ipsec_site_connection']['mtu'])
            self.assertEqual(['30.0.0.0/24', '31.0.0.0/24'],
                             res['ipsec_site_connection']['peer_cidrs'])
            self.assertEqual(45,
                             res['ipsec_site_connection']['dpd']['interval'])

            args = self.client_mock.update_ipsec_site_conn.call_args[0][2]
            self.assertEqual(1300, args['mtu'])
            self.assertEqual(['30.0.0.0/24', '31.0.0.0/24'],
                             args['peer_cidrs'])
            self.assertEqual(45, args['dpd_interval'])

    def test_update_ipsec_site_connection_error(self):
        self.client_mock.update_ipsec_site_conn.side_effect = Exception(
                "Fake Error")
        with self.ipsec_site_connection() as ipsec_site_connection:
            data = {'ipsec_site_connection': {'mtu': '1300'}}
            ipsec_site_conn_id = (
                   ipsec_site_connection['ipsec_site_connection']['id'])
            req = self.new_update_request('ipsec-site-connections', data,
                                          ipsec_site_conn_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(500, res.status_int)

            req = self.new_show_request('ipsec-site-connections',
                    ipsec_site_conn_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(n_const.ERROR,
                    res['ipsec_site_connection']['status'])

    def test_delete_ipsec_site_connection(self):
        with self.ipsec_site_connection(name="site_conn2",
                do_delete=False) as ipsec_site_connection:
            ipsec_site_conn_id = \
                    ipsec_site_connection['ipsec_site_connection']['id']
            req = self.new_delete_request('ipsec-site-connections',
                    ipsec_site_conn_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)

    def test_delete_ipsec_site_connection_error(self):
        self.client_mock.delete_ipsec_site_conn.side_effect = Exception(
            "Fake Error on delete_ipsec_site_conn")
        self.test_delete_ipsec_site_connection()
        req = self.new_list_request('ipsec-site-connections')
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertFalse(res['ipsec_site_connections'])
