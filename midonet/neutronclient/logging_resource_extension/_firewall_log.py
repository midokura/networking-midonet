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

from neutronclient.common import extension
from neutronclient import i18n
from neutronclient.neutron import v2_0 as loggingV20


_ = i18n._


def add_common_paramaters_to_arguments(parser):
    parser.add_argument(
        '--description', dest='description',
        help=_('Description of firewall log.'))
    parser.add_argument(
        '--fw-event', dest='fw_event',
        metavar='<ALL | ACCEPT | DROP>',
        choices=['ALL', 'ACCEPT', 'DROP'],
        help=_('Event of firewall. Defaults to ALL.'))


def _get_logging_resource_id(client, logging_resource_id_or_name):
    return loggingV20.find_resourceid_by_name_or_id(
            client, 'logging_resource',
            logging_resource_id_or_name)


class FirewallLog(extension.NeutronClientExtension):
    parent_resource = 'logging_resources'
    resource = 'firewall_log'
    resource_plural = 'firewall_logs'
    object_path = '/logging/%s/%%s/%s' % (parent_resource, resource_plural)
    resource_path = '/logging/%s/%%s/%s/%%%%s' % (parent_resource,
                                                  resource_plural)
    versions = ['2.0']

    def add_known_arguments(self, parser):
        parser.add_argument(
            'logging_resource', metavar='LOGGING_RESOURCE',
            help=_('ID of the logging_resource.'))
        add_common_paramaters_to_arguments(parser)

    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_logging_resource_id(self.get_client(),
                                                  parsed_args.logging_resource)


class FirewallLogCreate(extension.ClientExtensionCreate, FirewallLog):
    """Create Logging Resource Firewall Log information."""

    shell_command = 'logging-firewall-create'

    def get_parser(self, parser):
        parser = super(loggingV20.CreateCommand, self).get_parser(parser)
        self.add_known_arguments(parser)
        parser.add_argument(
            '--firewall-id', dest='firewall_id',
            required=True,
            help=_('Firewall to be logged'))
        return parser

    def args2body(self, args):
        body = {}
        attributes = ['firewall_id', 'description', 'fw_event']
        loggingV20.update_dict(args, body, attributes)
        return {'firewall_log': body}

    def run(self, parsed_args):
        def _extend_create(parent_id, body=None):
            return neutron_client.create_ext(
                     FirewallLog.object_path % parent_id,
                     body)

        neutron_client = self.get_client()
        setattr(neutron_client, "create_%s" % FirewallLog.resource,
                _extend_create)
        super(FirewallLogCreate, self).run(parsed_args)


class FirewallLogList(extension.ClientExtensionList, FirewallLog):
    """List Logging Resource Firewall Logs."""

    shell_command = 'logging-firewall-list'
    list_columns = ['id', 'firewall_id', 'fw_event']
    pagination_support = True
    sorting_support = True

    def run(self, parsed_args):
        def _extend_list(parent_id, **_params):
            return neutron_client.list_ext(
                     FirewallLog.object_path % parent_id,
                     **_params)
        neutron_client = self.get_client()
        setattr(neutron_client, "list_%s" % FirewallLog.resource_plural,
                _extend_list)

        super(FirewallLogList, self).run(parsed_args)


class FirewallLogShow(extension.ClientExtensionShow, FirewallLog):
    """Show information of a given Logging Resource Firewall Log."""

    shell_command = 'logging-firewall-show'
    allow_names = False

    def run(self, parsed_args):
        def _extend_show(obj, parent_id, **_params):
            return neutron_client.show_ext(
                     FirewallLog.resource_path % parent_id,
                     obj,
                     **_params)
        neutron_client = self.get_client()
        setattr(neutron_client, "show_%s" % FirewallLog.resource,
                _extend_show)

        super(FirewallLogShow, self).run(parsed_args)


class FirewallLogDelete(extension.ClientExtensionDelete, FirewallLog):
    """Delete a given Logging Resource Firewall Log."""

    shell_command = 'logging-firewall-delete'
    allow_names = False

    def run(self, parsed_args):
        def _extend_delete(obj, parent_id):
            return neutron_client.delete_ext(
                     FirewallLog.resource_path % parent_id,
                     obj)
        neutron_client = self.get_client()
        setattr(neutron_client, "delete_%s" % FirewallLog.resource,
                _extend_delete)

        super(FirewallLogDelete, self).run(parsed_args)


class FirewallLogUpdate(extension.ClientExtensionUpdate, FirewallLog):
    """Update a given Logging Resource Firewall Log."""

    shell_command = 'logging-firewall-update'

    def args2body(self, args):
        body = {}
        attributes = ['description', 'fw_event']
        loggingV20.update_dict(args, body, attributes)

        return {'firewall_log': body}

    def run(self, parsed_args):
        def _extend_update(obj, parent_id, body=None):
            return neutron_client.update_ext(
                     FirewallLog.resource_path % parent_id,
                     obj,
                     body)
        neutron_client = self.get_client()
        setattr(neutron_client, "update_%s" % FirewallLog.resource,
                _extend_update)

        super(FirewallLogUpdate, self).run(parsed_args)
