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
import functools
import mock

from midonet.neutron.tests.unit import (test_midonet_plugin_v2
    as test_mn_plugin_v2)
from midonet.neutron.tests.unit import midonet_client_mock
from midonet.neutron.tests.unit import sg_client_mock as sgc_mock
from midonet.neutron.tests.unit import test_midonet_plugin as test_mn_plugin

from neutron import context
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_agent

from oslo_config import cfg

PLUGIN_NAME = 'midonet.neutron.plugin_rsg.MidonetRegionalSGPlugin'
SG_CLIENT = 'midonet.neutron.client.sg_client'

sgc_patcher_map = {
    'sg_client_create_sg_patcher': 'create_security_group',
    'sg_client_delete_sg_patcher': 'delete_security_group',
    'sg_client_update_sg_patcher': 'update_security_group',
    'sg_client_get_sgs_patchter': 'get_security_groups',
    'sg_client_get_sg_patcher': 'get_security_group',
    'sg_client_create_sg_rule_patcher': 'create_security_group_rule',
    'sg_client_delete_sg_rule_patcher': 'delete_security_group_rule',
    'sg_client_get_sg_rules_patcher': 'get_security_group_rules',
    'sg_client_get_sg_rule_patcher': 'get_security_group_rule',
    'sg_client_create_portbinding_patcher': 'create_portbinding',
    'sg_client_update_portbinding_patcher': 'update_portbinding',
    'sg_client_delete_portbinding_patcher': 'delete_portbinding',
    'sg_client_get_portbindings_patcher': 'get_portbindings',
    'sg_client_get_portbinding_patcher': 'get_portbinding',
    'sg_client_get_sgs_by_ids_patcher': 'get_security_groups_by_ids'}

midoc_mock_list = [
    'create_security_group_postcommit',
    'delete_security_group_postcommit',
    'create_security_group_rule_postcommit',
    'delete_security_group_rule_postcommit',
    'get_security_groups',
    'get_ipaddr_group_addrs',
    'create_ipaddr_group_addr',
    'delete_ipaddr_group_addr']


class MidonetRegionalSGPluginTestCase(
                                    test_mn_plugin_v2.MidonetPluginV2TestCase):

    def setup_parent(self, service_plugins=None, ext_mgr=None):

        # Set up mock for the midonet client to be made available in tests
        patcher = mock.patch(test_mn_plugin.TEST_MN_CLIENT)
        self.client_mock = mock.MagicMock()
        patcher.start().return_value = self.client_mock

        # Ensure that sync_sg_service can be called in setUp
        self.sync_sg_patch = mock.patch(
            PLUGIN_NAME + '.start_periodic_sync_sg_service')
        self.sync_sg_loop = self.sync_sg_patch.start()

        # Ensure that the parent setup can be called without arguments
        # by the common configuration setUp.
        plugin_name = PLUGIN_NAME
        parent_setup = functools.partial(
            super(test_mn_plugin_v2.MidonetPluginV2TestCase, self).setUp,
            plugin=plugin_name,
            service_plugins=service_plugins,
            ext_mgr=ext_mgr,
        )
        test_mn_plugin.MidonetPluginConf.setUp(self, parent_setup)

    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):
        self.setup_parent(service_plugins=service_plugins, ext_mgr=ext_mgr)
        cfg.CONF.set_override('sync_sg_interval', 40)
        cfg.CONF.set_override('sync_sg_fuzzy_delay', 5)
        # initialize sg_client mock
        for k, v in sgc_patcher_map.iteritems():
            exec("self.{patcher} = mock.patch(SG_CLIENT "
                 "+ \".{method}\")".format(patcher = k, method = v))
            exec("self.{patcher}.start().side_effect ="
                 " sgc_mock.{method}".format(patcher = k, method = v))
        # initialize midonet_client mock
        self.mido_mock = midonet_client_mock.LocalMidonetClient()
        for i in midoc_mock_list:
            exec("self.client_mock.{method}.side_effect = "
                 "self.mido_mock.{method}".format(method = i))
        # check loopingcall of sync_sg_service
        self.assertEqual(1, self.sync_sg_loop.call_count)

    def tearDown(self):
        sgc_mock.default_sg_cache = {}
        super(MidonetRegionalSGPluginTestCase, self).tearDown()


class TestMidonetRSGNetworksV2(MidonetRegionalSGPluginTestCase,
                               test_mn_plugin_v2.TestMidonetNetworksV2):
    pass


class TestMidonetRSGSubnetsV2(MidonetRegionalSGPluginTestCase,
                              test_mn_plugin_v2.TestMidonetSubnetsV2):
    pass


class TestMidonetRSGPortsV2(MidonetRegionalSGPluginTestCase,
                            test_mn_plugin_v2.TestMidonetPortsV2):
    # TODO(RegionalSG): need to implement
    pass


class TestMidonetRSGSecurityGroup(test_mn_plugin_v2.TestMidonetSecurityGroup,
                                  MidonetRegionalSGPluginTestCase):
    # TODO(RegionalSG): need to implement
    pass


class TestMidonetRSGPortBinding(MidonetRegionalSGPluginTestCase,
                                test_mn_plugin_v2.TestMidonetPortBinding):
    pass


class TestMidonetRSGExtGwMode(test_mn_plugin_v2.TestMidonetExtGwMode,
                              MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGExtraDHCPOpts(test_mn_plugin_v2.TestMidonetExtraDHCPOpts,
                                  MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGL3NatExtraRoute(
        test_mn_plugin_v2.TestMidonetL3NatExtraRoute,
        MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGDataState(test_mn_plugin_v2.TestMidonetDataState,
                              MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGAgent(MidonetRegionalSGPluginTestCase,
                          test_mn_plugin_v2.TestMidonetAgent):
    def setUp(self):
        super(TestMidonetRSGAgent, self).setUp()
        self.adminContext = context.get_admin_context()
        ext_mgr = test_agent.AgentTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)


class TestMidonetRSGDataVersion(test_mn_plugin_v2.TestMidonetDataVersion,
                                MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGProviderNet(test_mn_plugin_v2.TestMidonetProviderNet,
                                MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGAllowedAddressPair(
        test_mn_plugin_v2.TestMidonetAllowedAddressPair,
        MidonetRegionalSGPluginTestCase):
    pass


class TestMidonetRSGPortSecurity(test_mn_plugin_v2.TestMidonetPortSecurity,
                                 MidonetRegionalSGPluginTestCase):
    pass
