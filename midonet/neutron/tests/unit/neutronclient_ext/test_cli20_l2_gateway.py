# Copyright (C) 2016 Midokura SARL
# Copyright 2015 OpenStack Foundation.
# All Rights Reserved
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
#

import sys

import mock

from midonet.neutron.tests.unit.neutronclient_ext import test_cli20
from midonet.neutronclient.l2gateway_extension import (
    _l2_gateway as l2_gateway)

from neutronclient import shell


class CLITestV20ExtensionL2GWJSON(test_cli20.CLIExtTestV20Base):
    def setUp(self):
        # need to mock before super because extensions loaded on instantiation
        self._mock_extension_loading()
        super(CLITestV20ExtensionL2GWJSON, self).setUp(plurals={'tags': 'tag'})

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        contrib = self._create_patch(ext_pkg + '._discover_via_entry_points')
        contrib.return_value = [("_l2_gateway", l2_gateway)]
        return contrib

    def test_ext_cmd_loaded(self):
        """Tests l2gw  commands loaded."""
        shell.NeutronShell('2.0')
        ext_cmd = {'l2-gateway-list': l2_gateway.L2GatewayList,
                   'l2-gateway-create': l2_gateway.L2GatewayCreate,
                   'l2-gateway-delete': l2_gateway.L2GatewayDelete,
                   'l2-gateway-show': l2_gateway.L2GatewayShow}
        self.assertDictContainsSubset(ext_cmd, shell.COMMANDS['2.0'])

    def _create_l2gateway(self, name, args,
                          position_names, position_values):
        resource = 'l2_gateway'
        cmd = l2_gateway.L2GatewayCreate(
                                        test_cli20.MyApp(sys.stdout), None)
        self._test_create_resource(resource, cmd, name, 'myid',
                                   args, position_names, position_values)

    def test_create_l2gateway(self):
        name = 'l2gateway1'
        args = [name, '--device',
                'device_id=my_device_id,segmentation_id=my_segmentation_id']
        position_names = ['name', 'devices']
        position_values = [name, [{"device_id": "my_device_id",
                                  "segmentation_id": "my_segmentation_id"}]]
        self._create_l2gateway(name, args,
                               position_names, position_values)

    def test_create_l2gateway_with_multiple_devices(self):
        name = 'l2gateway1'
        args = [name,
                '--device',
                'device_id=my_device_id1,segmentation_id=my_segmentation_id1',
                '--device',
                'device_id=my_device_id2,segmentation_id=my_segmentation_id2']
        position_names = ['name', 'devices']
        position_values = [name,
                           [{"device_id": "my_device_id1",
                             "segmentation_id": "my_segmentation_id1"},
                            {"device_id": "my_device_id2",
                             "segmentation_id": "my_segmentation_id2"}]]
        self._create_l2gateway(name, args,
                               position_names, position_values)

    def test_create_l2gateway_without_segmentation_id(self):
        name = 'l2gateway1'
        args = [name, '--device', 'device_id=my_device_id']
        position_names = ['name', 'devices']
        position_values = [name, [{"device_id": "my_device_id"}]]
        self._create_l2gateway(name, args,
                               position_names, position_values)

    def test_list_l2gateway(self):
        """Test List l2gateways."""

        resources = "l2_gateways"
        cmd = l2_gateway.L2GatewayList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_delete_l2gateway(self):
        """Test Delete l2gateway."""

        resource = 'l2_gateway'
        cmd = l2_gateway.L2GatewayDelete(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)

    def test_show_l2gateway(self):
        """Test Show l2gateway: --fields id --fields name myid."""

        resource = 'l2_gateway'
        cmd = l2_gateway.L2GatewayShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args,
                                 ['id', 'name'])
