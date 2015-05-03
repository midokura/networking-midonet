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

import mock

from neutron.extensions import portbindings
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions import test_l3_ext_gw_mode as test_gw_mode
from neutron.tests.unit.extensions import test_securitygroup as test_sg
import sys
sys.modules["midonetclient"] = mock.Mock()
sys.modules["midonetclient.neutron"] = mock.Mock()
sys.modules["midonetclient.neutron.client"] = mock.Mock()


MIDOKURA_PKG_PATH = 'neutron.plugins.midonet.plugin'
MIDONET_PLUGIN_NAME = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)


class MidonetPluginApiV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=MIDONET_PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(MidonetPluginApiV2TestCase, self).setUp(plugin=plugin)

    def tearDown(self):
        super(MidonetPluginApiV2TestCase, self).tearDown()


class TestMidonetNetworksV2(MidonetPluginApiV2TestCase,
                            test_plugin.TestNetworksV2):

    pass


class TestMidonetL3NatTestCase(MidonetPluginApiV2TestCase,
                               test_l3_plugin.L3NatDBIntTestCase):

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(MIDONET_PLUGIN_NAME)


class TestMidonetSecurityGroup(MidonetPluginApiV2TestCase,
                               test_sg.TestSecurityGroups):

    pass


class TestMidonetSubnetsV2(MidonetPluginApiV2TestCase,
                           test_plugin.TestSubnetsV2):

    pass


class TestMidonetPortsV2(MidonetPluginApiV2TestCase,
                         test_plugin.TestPortsV2):

    def test_vif_port_binding(self):
        with self.port(name='myname') as port:
            self.assertEqual('midonet', port['port']['binding:vif_type'])
            self.assertTrue(port['port']['admin_state_up'])


class TestMidonetPluginPortBinding(MidonetPluginApiV2TestCase,
                                   test_bindings.PortBindingsTestCase):

    VIF_TYPE = portbindings.VIF_TYPE_MIDONET
    HAS_PORT_FILTER = True


class TestExtGwMode(MidonetPluginApiV2TestCase,
                    test_gw_mode.ExtGwModeIntTestCase):

    pass


class TestExtraDHCPOpts(MidonetPluginApiV2TestCase,
                        test_dhcpopts.TestExtraDhcpOpt):
    pass