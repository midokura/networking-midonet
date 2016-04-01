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


from midonet.neutron.services.l2gateway.common import l2gw_midonet_validators
from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.db.l2gateway import l2gateway_models as models
from networking_l2gw.services.l2gateway.common import constants


class MidonetL2GatewayMixin(l2gateway_db.L2GatewayMixin):
    # Override L2GatewayMixin to customize for Midonet L2GW

    def _validate_any_seg_id_empty_in_interface_dict(self, devices):
        # HACK: Override this since this validation method is not
        # applicable in MidoNet.
        pass

    def _get_l2_gateway_seg_id(self, context, l2_gw_id):
        seg_id = None
        l2_gw_dev = self.get_l2gateway_devices_by_gateway_id(
                    context, l2_gw_id)
        interfaces = self.get_l2gateway_interfaces_by_device_id(
                    context, l2_gw_dev[0]['id'])
        if interfaces:
            seg_id = interfaces[0][constants.SEG_ID]
        return seg_id

    def _get_l2gw_devices_by_device_id(self, context, device_id):
        return context.session.query(models.L2GatewayDevice).filter_by(
            device_name=device_id).all()

    def create_l2_gateway(self, context, l2_gateway):
        # HACK: set the device_name to device_id so that the networking-l2gw
        # DB class does not throw an error.
        gw = l2_gateway[self.gateway_resource]
        for device in gw['devices']:
            device['device_name'] = device['device_id']
            if device.get(constants.SEG_ID):
                l2gw_midonet_validators.is_valid_vxlan_id(
                        device[constants.SEG_ID])
                device['interfaces'].append(
                    {constants.SEG_ID: [str(device[constants.SEG_ID])]})
        return super(MidonetL2GatewayMixin, self).create_l2_gateway(
            context, l2_gateway)

    def _make_l2_gateway_dict(self, l2_gateway, fields=None):
        l2gw = super(MidonetL2GatewayMixin, self)._make_l2_gateway_dict(
            l2_gateway, fields=fields)

        # HACK: change the 'device_name' to 'device_id' to match the API that
        # Midonet L2GW expects
        if 'devices' in l2gw:
            for device in l2gw['devices']:
                device['device_id'] = device['device_name']
                if device['interfaces']:
                    device[constants.SEG_ID] = \
                            device['interfaces'][0][constants.SEG_ID][0]
                del device['device_name']
                del device['id']
                del device['interfaces']
        return l2gw

    def update_l2_gateway(self, context, id, l2_gateway):
        raise NotImplementedError()
