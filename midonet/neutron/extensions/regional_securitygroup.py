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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron import manager


REGIONAL_SECURITYGROUP = 'security_group_update'
REGIONAL_SECURITYGROUPS = '%ss' % REGIONAL_SECURITYGROUP

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'security_group_updates': {
        'security_group_changes': {'allow_post': True,
                                   'allow_put': False,
                                   'is_visible': True,
                                   'default': []},
        'security_groups': {'allow_post': True, 'allow_put': False,
                            'is_visible': True, 'default': []},
        'security_group_source_groups': {'allow_post': True,
                                         'allow_put': False,
                                         'is_visible': True,
                                         'default': []},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False}
    }
}


class Regional_securitygroup(extensions.ExtensionDescriptor):
    """Regional Securitygroup extension."""

    @classmethod
    def get_name(cls):
        return "Midonet Regional SecurityGroup Extension"

    @classmethod
    def get_alias(cls):
        return "regional-security-group"

    @classmethod
    def get_description(cls):
        return "The regional security groups extension."

    @classmethod
    def get_namespace(cls):
        # todo
        return "http://docs.openstack.org/ext/securitygroups/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2015-11-26T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_plugin()

        resource_name = REGIONAL_SECURITYGROUP
        collection_name = REGIONAL_SECURITYGROUPS.replace('_', '-')
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        regional_sg_controller = base.create_resource(collection_name,
                                                      resource_name,
                                                      plugin, params)
        ex = extensions.ResourceExtension(collection_name,
                                          regional_sg_controller)
        exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class RegionalSecurityGroupPluginBase(object):

    @abc.abstractmethod
    def create_security_group_update(self, context, security_group_update):
        pass
