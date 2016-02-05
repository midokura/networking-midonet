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
import random

from midonet.neutron.db import regional_securitygroup_db as rsg_db
from midonet.neutron import plugin_v2

from neutron.api.v2 import attributes
from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron import context as ncontext
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import portsecurity as psec
from neutron.extensions import securitygroup as ext_sg
from neutron import i18n
from neutron.openstack.common import loopingcall

from oslo_config import cfg

from oslo_log import log as logging

from oslo_utils import excutils

cfg.CONF.register_opt(cfg.IntOpt('sync_sg_interval',
                                 default=40,
                                 help="Seconds between running "
                                 "sync_sg_service"))
cfg.CONF.register_opt(cfg.IntOpt('sync_sg_fuzzy_delay',
                                 default=5,
                                 help="Range of seconds to randomly delay "
                                 "when starting sync_sg_service."
                                 "(Disable by setting to 0)"))

LOG = logging.getLogger(__name__)
_LE = i18n._LE
_LW = i18n._LW


# Based on MidonetPluginV2
class MidonetRegionalSGPlugin(rsg_db.RegionalSecurityGroupDbMixin,
                              plugin_v2.MidonetPluginV2):

    supported_extension_aliases = [
        'agent',
        'agent-membership',
        'allowed-address-pairs',
        'binding',
        'dhcp_agent_scheduler',
        'external-net',
        'extra_dhcp_opt',
        'extraroute',
        'port-security',
        'provider',
        'quotas',
        'router',
        'security-group',
        'regional-security-group'  # Added for RegionalSG
    ]

    # RegionManager doesn't support bulk_create
    __native_bulk_support = False

    def __init__(self):
        super(MidonetRegionalSGPlugin, self).__init__()
        self.client.initialize()
        self.sync_sg_interval = cfg.CONF.sync_sg_interval
        self.sync_sg_fuzzy_delay = cfg.CONF.sync_sg_fuzzy_delay
        # Start periodic_sync_sg_service
        self.start_periodic_sync_sg_service()

    def setup_sync_sg_service(self, f):
        self.periodic_sync_loop = loopingcall.FixedIntervalLoopingCall(f)
        if self.sync_sg_fuzzy_delay:
            initial_delay = random.randint(0, self.sync_sg_fuzzy_delay)
        else:
            initial_delay = None
        self.periodic_sync_loop.start(interval=self.sync_sg_interval,
                                      initial_delay=initial_delay)

    def start_periodic_sync_sg_service(self):
        self.setup_sync_sg_service(self.sync_sg_service)

    def create_port(self, context, port):
        LOG.debug("MidonetRegionalSGPlugin.create_port called: port=%r", port)

        # NOTE(RegionalSG): Check security group beforehand
        port_psec, has_ip = self._determine_port_security_and_has_ip(
                                                        context, port['port'])

        port_data = port['port']
        with context.session.begin(subtransactions=True):
            # Create a Neutron port
            new_port = super(plugin_v2.MidonetPluginV2, self).create_port(
                                                                context, port)

            # Do not create a gateway port if it has no IP address assigned as
            # MidoNet does not yet handle this case.
            if (new_port.get('device_owner') == n_const.DEVICE_OWNER_ROUTER_GW
                    and not new_port['fixed_ips']):
                msg = (_("No IPs assigned to the gateway port for"
                         " router %s") % port_data['device_id'])
                raise n_exc.BadRequest(resource='router', msg=msg)

            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])

            # Make sure that the port created is valid
            if "id" not in new_port:
                raise n_exc.BadRequest(resource='port',
                                       msg="Invalid port created")

            # Update fields
            port_data.update(new_port)

            port['port'][psec.PORTSECURITY] = port_psec
            self._process_port_port_security_create(context,
                                                    port['port'],
                                                    new_port)

            if port_psec is False:
                if self._check_update_has_security_groups(port):
                    raise psec.PortSecurityAndIPRequiredForSecurityGroups()
                if self._check_update_has_allowed_address_pairs(port):
                    raise addr_pair.AddressPairAndPortSecurityRequired()

            # Process port bindings
            self._process_portbindings_create_and_update(context, port_data,
                                                         new_port)
            self._process_mido_portbindings_create_and_update(context,
                                                              port_data,
                                                              new_port)

            self._process_port_create_extra_dhcp_opts(context, new_port,
                                                      dhcp_opts)

            new_port[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, new_port,
                    port_data.get(addr_pair.ADDRESS_PAIRS)))

            self.client.create_port_precommit(context, new_port)

        try:
            if port_psec:
                # NOTE(RegionalSG): returns _get_security_groups_on_port
                sgids = self._ensure_default_security_group_on_port(context,
                                                                    port)
                self._process_port_create_security_group(context,
                                                         new_port, sgids)

            self.client.create_port_postcommit(new_port)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create a port %(new_port)s: %(err)s"),
                          {"new_port": new_port, "err": ex})
                try:
                    self.delete_port(context, new_port['id'],
                                     l3_port_check=False)
                except Exception:
                    LOG.exception(_LE("Failed to delete port %s"),
                                  new_port['id'])

        LOG.debug("MidonetRegionalSGPlugin.create_port exiting: "
                  "port=%r", new_port)
        return new_port

    def delete_port(self, context, id, l3_port_check=True):
        LOG.debug("MidonetRegionalSGPlugin.delete_port called: id=%(id)s "
                  "l3_port_check=%(l3_port_check)r",
                  {'id': id, 'l3_port_check': l3_port_check})

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        with context.session.begin(subtransactions=True):
            super(plugin_v2.MidonetPluginV2, self).disassociate_floatingips(
                context, id, do_notify=False)
            super(plugin_v2.MidonetPluginV2, self).delete_port(context, id)
            self.client.delete_port_precommit(context, id)

        # NOTE(RegionalSG): delete sg-port map on SG service
        try:
            self._process_port_delete_security_group(context, id)
        except Exception:
            LOG.exception(_LE("SG service delete portbinding failed. "
                              "port id: %s"), id)

        self.client.delete_port_postcommit(id)

        LOG.debug("MidonetRegionalSGPlugin.delete_port exiting: id=%r", id)

    def update_port(self, context, id, port):
        LOG.debug("MidonetRegionalSGPlugin.update_port called: id=%(id)s "
                  "port=%(port)r", {'id': id, 'port': port})

        attrs = port[attributes.PORT]
        # NOTE(RegionalSG):
        # Get security group info from SG service for portsecurity validation
        security_groups = None
        if (psec.PORTSECURITY in attrs and
            not attrs[psec.PORTSECURITY] and
                not self._check_update_deletes_security_groups(port)):

            security_groups = self._get_port_security_groups(context, id)

        # NOTE(RegionalSG): Check security group beforehand
        save_e = None
        if ext_sg.SECURITYGROUPS in attrs:
            try:
                self._get_security_groups_on_port(context, port)
            except Exception as e:
                save_e = e

        with context.session.begin(subtransactions=True):

            # update the port DB
            original_port = super(MidonetRegionalSGPlugin,
                                  self).get_port(context, id)
            p = super(plugin_v2.MidonetPluginV2,
                      self).update_port(context, id, port)

            if save_e:
                raise save_e

            self._update_extra_dhcp_opts_on_port(context, id, port, p)

            self._process_portbindings_create_and_update(context,
                                                         port['port'], p)
            self._process_mido_portbindings_create_and_update(context,
                                                              port['port'], p)
            self.update_address_pairs_on_port(context, id, port,
                                              original_port, p)

            self._process_port_port_security_update(context, port['port'], p)

            port_psec = p.get(psec.PORTSECURITY)
            if port_psec is False:
                if security_groups:
                    raise psec.PortSecurityPortHasSecurityGroup()
                if p.get(addr_pair.ADDRESS_PAIRS):
                    raise addr_pair.AddressPairAndPortSecurityRequired()

            self.client.update_port_precommit(context, id, p)

        # NOTE(RegionalSG): update sg-port map on SG service
        self.update_security_group_on_port(context, id, port, original_port, p)

        self.client.update_port_postcommit(id, p)

        LOG.debug("MidonetRegionalSGPlugin.update_port exiting: p=%r", p)
        return p

    # (RegionalSG)
    def get_port(self, context, id, fields=None):
        port = self._get_port(context, id)
        res = self._extend_port_security_group(context, [port], fields)
        return res[0]

    # (RegionalSG)
    # NOTE: limit, marker, etc. are not supported.
    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        ports = self._get_ports_query(context, filters=filters).all()
        return self._extend_port_security_group(context, ports, fields)

    def create_security_group(self, context, security_group, default_sg=False):
        LOG.debug("MidonetRegionalSGPlugin.create_security_group called: "
                  "security_group=%(security_group)s "
                  "default_sg=%(default_sg)s ",
                  {'security_group': security_group, 'default_sg': default_sg})

        sg = super(MidonetRegionalSGPlugin, self).create_security_group(
                context, security_group)

        LOG.debug("MidonetRegionalSGPlugin.create_security_group exiting: "
                  "sg=%r", sg)
        return sg

    def delete_security_group(self, context, id):
        LOG.debug("MidonetRegionalSGPlugin.delete_security_group called: "
                  "id=%s", id)
        # confirm security group exists
        self.get_security_group(context, id)

        super(MidonetRegionalSGPlugin, self).delete_security_group(context, id)

        LOG.debug("MidonetRegionalSGPlugin.delete_security_group exiting: "
                  "id=%r", id)

    def create_security_group_rule(self, context, security_group_rule):
        LOG.debug("MidonetRegionalSGPlugin.create_security_group_rule called: "
                  "security_group_rule=%(security_group_rule)r",
                  {'security_group_rule': security_group_rule})

        rule = super(MidonetRegionalSGPlugin,
                     self).create_security_group_rule(context,
                                                      security_group_rule)

        LOG.debug("MidonetRegionalSGPlugin.create_security_group_rule exiting:"
                  " rule=%r", rule)
        return rule

    def delete_security_group_rule(self, context, sg_rule_id):
        LOG.debug("MidonetRegionalSGPlugin.delete_security_group_rule called:"
                  " sg_rule_id=%s", sg_rule_id)
        # confirm security group rule exists
        self.get_security_group_rule(context, sg_rule_id)

        super(MidonetRegionalSGPlugin,
              self).delete_security_group_rule(context, sg_rule_id)

        LOG.debug("MidonetRegionalSGPlugin.delete_security_group_rule exiting:"
                  " id=%r", sg_rule_id)

    def create_security_group_update(self, context, security_group_update):
        LOG.debug("MidonetRegionalSGPlugin.create_security_group_update "
                  "called: security_group_update=%s", security_group_update)
        update = super(MidonetRegionalSGPlugin,
                       self).create_security_group_update(
                                                context, security_group_update)
        LOG.debug("MidonetRegionalSGPlugin.create_security_group_update "
                  "exiting: update=%r", update)
        return update

    def _collect_sg_info(self, context):
        mido_sgs = self.get_security_groups_from_midonet(context)
        sgs = self.get_security_groups_minimal(context)
        mido_sg_map = self._make_security_group_map(mido_sgs)
        sg_map = self._make_security_group_map(sgs)
        return (sg_map, mido_sg_map)

    def sync_sg_service(self):
        LOG.debug("MidonetRegionalSGPlugin.sync_sg_service started")
        context = ncontext.get_admin_context()
        try:
            sg_map, mido_sg_map = self._collect_sg_info(context)
            # sync security_groups
            sg_create = set(sg_map.keys()) - set(mido_sg_map.keys())
            sg_delete = set(mido_sg_map.keys()) - set(sg_map.keys())
            self.sync_security_groups(context, sg_create, sg_delete)
            # sync security_group_rules
            for id in sg_create:
                sg_map.pop(id)
            self.sync_security_group_rules(context, sg_map, mido_sg_map)
            # sync security_group_members
            self.sync_security_group_members(context, sg_map)
            LOG.debug("MidonetRegionalSGPlugin.sync_sg_service ended")
        except Exception as ex:
            # To avoid loop abortion
            LOG.exception(_LE("Unexpected exception occurred while syncing"
                              " sg service. (exception: %s)"), ex)
