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

from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient import i18n
from oslo_serialization import jsonutils

_ = i18n._


def _format_devices(l2_gateway):
    try:
        return '\n'.join([jsonutils.dumps(gateway) for gateway in
                          l2_gateway['devices']])
    except (TypeError, KeyError):
        return ''


class L2Gateway(extension.NeutronClientExtension):
    resource = 'l2_gateway'
    resource_plural = 'l2_gateways'
    path = 'l2-gateways'
    object_path = '/%s' % path
    resource_path = '/%s/%%s' % path
    versions = ['2.0']


def add_known_arguments(self, parser):
    parser.add_argument(
        '--device',
        metavar='device_id=DEVICE_ID,segmentaion_id=SEGMENTAION_ID',
        action='append', dest='devices', type=utils.str2dict,
        help=_('Device id and segmentation id of l2gateway. '
               '--device option can be repeated'))


def args2body(self, parsed_args):
        if parsed_args.devices:
            devices = parsed_args.devices
        else:
            devices = []
        body = {'l2_gateway': {'devices': devices}}
        if parsed_args.name:
            l2gw_name = parsed_args.name
            body['l2_gateway']['name'] = l2gw_name
        return body


class L2GatewayCreate(extension.ClientExtensionCreate, L2Gateway):
    """Create l2gateway information for midonet."""

    shell_command = 'l2-gateway-create'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name', metavar='GATEWAY-NAME',
            help=_('Descriptive name for logical gateway.'))
        add_known_arguments(self, parser)

    def args2body(self, parsed_args):
        body = args2body(self, parsed_args)
        if parsed_args.tenant_id:
            body['l2_gateway']['tenant_id'] = parsed_args.tenant_id
        return body


class L2GatewayList(extension.ClientExtensionList, L2Gateway):
    """List l2gateway that belongs to a given tenant."""

    shell_command = 'l2-gateway-list'
    _formatters = {'devices': _format_devices, }
    list_columns = ['id', 'name', 'devices']
    pagination_support = True
    sorting_support = True


class L2GatewayShow(extension.ClientExtensionShow, L2Gateway):
    """Show information of a given l2gateway."""

    shell_command = 'l2-gateway-show'


class L2GatewayDelete(extension.ClientExtensionDelete, L2Gateway):
    """Delete a given l2gateway."""

    shell_command = 'l2-gateway-delete'
