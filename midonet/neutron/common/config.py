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

from neutron import i18n  # noqa
from oslo_config import cfg


mido_opts = [
    cfg.StrOpt('midonet_uri', default='http://localhost:8080/midonet-api',
               help=_('MidoNet API server URI.')),
    cfg.StrOpt('username', default='admin',
               help=_('MidoNet admin username.')),
    cfg.StrOpt('password', default='passw0rd',
               secret=True,
               help=_('MidoNet admin password.')),
    cfg.StrOpt('project_id',
               default='77777777-7777-7777-7777-777777777777',
               help=_('ID of the project that MidoNet admin user '
                      'belongs to.')),
    cfg.StrOpt('tunnel_protocol', default='vxlan',
               help=_('Tunnel protocol used by Midonet')),
    cfg.StrOpt('cluster_ip', default='localhost',
               help=_('IP that the cluster service can be reached on')),
    cfg.StrOpt('cluster_port', default='8088',
               help=_('Port that the cluster service can be reached on')),
    cfg.StrOpt('client', default='midonet.neutron.client.api.MidonetApiClient',
               help=_('MidoNet client used to access MidoNet data storage.')),
]

cfg.CONF.register_opts(mido_opts, "MIDONET")

# The Neutron Kilo version FWaaS plugin expects the router_distrubted option
# to be present in the config. However, in this plugin version we do not load
# the module that creates this option. Create the option here to work around
# this.
other_opts = [
    cfg.BoolOpt('router_distributed',
    default=False,
    help=_("System-wide flag to determine the type of router "
           "that tenants can create. Only admin can override."))
]

cfg.CONF.register_opts(other_opts)
