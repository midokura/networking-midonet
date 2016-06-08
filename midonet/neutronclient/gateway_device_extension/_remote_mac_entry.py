# Copyright (C) 2016 Midokura SARL
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutronclient.common import extension
from neutronclient import i18n
from neutronclient.neutron import v2_0 as gw_deviceV20


_ = i18n._


def _get_gateway_device_id(client, gw_device_id_or_name):
    return gw_deviceV20.find_resourceid_by_name_or_id(client, 'gateway_device',
                                                      gw_device_id_or_name)


class RemoteMacEntry(extension.NeutronClientExtension):
    parent_resource = 'gateway_devices'
    resource = 'remote_mac_entry'
    resource_plural = 'remote_mac_entries'
    object_path = '/gw/%s/%%s/%s' % (parent_resource, resource_plural)
    resource_path = '/gw/%s/%%s/%s/%%%%s' % (parent_resource, resource_plural)
    versions = ['2.0']

    def add_known_arguments(self, parser):
        parser.add_argument(
            'gateway_device', metavar='GATEWAY_DEVICE',
            help=_('ID of the gateway device.'))

    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_gateway_device_id(self.get_client(),
                                                parsed_args.gateway_device)


class RemoteMacEntryCreate(extension.ClientExtensionCreate, RemoteMacEntry):
    """Create Gateway Device Remote Mac Entry information."""

    shell_command = 'gateway-device-remote-mac-entry-create'

    def get_parser(self, parser):
        parser = super(gw_deviceV20.CreateCommand, self).get_parser(parser)
        parser.add_argument(
            '--mac-address', dest='mac_address',
            required=True,
            help=_('Remote MAC address'))
        parser.add_argument(
            '--vtep-address', dest='vtep_address',
            required=True,
            help=_('Remote VTEP Tunnel IP'))
        parser.add_argument(
            '--segmentation-id', dest='segmentation_id',
            required=True,
            help=_('VNI to be used'))
        self.add_known_arguments(parser)
        return parser

    def args2body(self, args):
        body = {}
        attributes = ['mac_address', 'vtep_address', 'segmentation_id']
        gw_deviceV20.update_dict(args, body, attributes)
        return {'remote_mac_entry': body}

    def run(self, parsed_args):
        def _extend_create(parent_id, body=None):
            return neutron_client.create_ext(
                     RemoteMacEntry.object_path % parent_id,
                     body)

        neutron_client = self.get_client()
        setattr(neutron_client, "create_%s" % RemoteMacEntry.resource,
                _extend_create)
        super(RemoteMacEntryCreate, self).run(parsed_args)


class RemoteMacEntryList(extension.ClientExtensionList, RemoteMacEntry):
    """List Gateway Device Remote Mac Entries."""

    shell_command = 'gateway-device-remote-mac-entry-list'
    list_columns = ['id', 'mac_address', 'vtep_address', 'segmentation_id']
    pagination_support = True
    sorting_support = True

    def run(self, parsed_args):
        def _extend_list(parent_id, **_params):
            return neutron_client.list_ext(
                     RemoteMacEntry.object_path % parent_id,
                     **_params)
        neutron_client = self.get_client()
        setattr(neutron_client, "list_%s" % RemoteMacEntry.resource_plural,
                _extend_list)

        # Add this entry since upstream doesn't handle resource_plural in kilo.
        neutron_client.EXTED_PLURALS[RemoteMacEntry.resource_plural] = (
                                        RemoteMacEntry.resource)

        super(RemoteMacEntryList, self).run(parsed_args)


class RemoteMacEntryShow(extension.ClientExtensionShow, RemoteMacEntry):
    """Show information of a given gateway-device-remote-mac-entry."""

    shell_command = 'gateway-device-remote-mac-entry-show'
    allow_names = False

    def run(self, parsed_args):
        def _extend_show(obj, parent_id, **_params):
            return neutron_client.show_ext(
                     RemoteMacEntry.resource_path % parent_id,
                     obj,
                     **_params)
        neutron_client = self.get_client()
        setattr(neutron_client, "show_%s" % RemoteMacEntry.resource,
                _extend_show)

        super(RemoteMacEntryShow, self).run(parsed_args)


class RemoteMacEntryDelete(extension.ClientExtensionDelete, RemoteMacEntry):
    """Delete a given gateway-device-remote-mac-entry."""

    shell_command = 'gateway-device-remote-mac-entry-delete'
    allow_names = False

    def run(self, parsed_args):
        def _extend_delete(obj, parent_id):
            return neutron_client.delete_ext(
                     RemoteMacEntry.resource_path % parent_id,
                     obj)
        neutron_client = self.get_client()
        setattr(neutron_client, "delete_%s" % RemoteMacEntry.resource,
                _extend_delete)

        super(RemoteMacEntryDelete, self).run(parsed_args)
