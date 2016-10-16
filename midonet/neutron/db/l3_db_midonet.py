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

from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import utils
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.plugins.common import utils as p_utils

DEVICE_OWNER_FLOATINGIP = n_const.DEVICE_OWNER_FLOATINGIP


class MidonetL3DBMixin(l3_gwmode_db.L3_NAT_db_mixin):
    # TODO(kengo): This is temporary workaround until upstream adds a check
    # for router deletion in l3_db

    def _check_router_not_in_use(self, context, router_id):
        try:
            kwargs = {'context': context, 'router_id': router_id}
            registry.notify(
                resources.ROUTER, events.BEFORE_DELETE, self, **kwargs)
        except exceptions.CallbackFailure as e:
            with excutils.save_and_reraise_exception():
                if len(e.errors) == 1:
                    raise e.errors[0].error
                raise l3.RouterInUse(router_id=router_id, reason=e)

    def _port_ipv6_fixed_ips(self, port):
        return [ip for ip in port['fixed_ips']
                if netaddr.IPAddress(ip['ip_address']).version == 6]

    # REVISIT(bikfalvi): This method is a copy of the base class method,
    # to allow IPv6 by substituting the calls to _is_ipv4_network and
    # _port_ipv4_fixed_ips by equivalent code that allow both IPv6 and IPv4 FIPs.
    # Additionally, a call to delete_port has been added in case the port cannot
    # be created.
    def _create_floatingip(self, context, floatingip,
                           initial_status=n_const.FLOATINGIP_STATUS_ACTIVE):
        fip = floatingip['floatingip']
        fip_id = uuidutils.generate_uuid()

        f_net_id = fip['floating_network_id']
        if not self._core_plugin._network_is_external(context, f_net_id):
            msg = _("Network %s is not a valid external network") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        if not any(self._core_plugin._get_network(context, f_net_id).subnets):
            msg = _("Network %s does not contain any subnet") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        dns_integration = utils.is_extension_supported(self._core_plugin,
                                                       'dns-integration')
        with context.session.begin(subtransactions=True):
            # This external port is never exposed to the tenant.
            # it is used purely for internal system and admin use when
            # managing floating IPs.

            port = {'tenant_id': '',  # tenant intentionally not set
                    'network_id': f_net_id,
                    'admin_state_up': True,
                    'device_id': fip_id,
                    'device_owner': DEVICE_OWNER_FLOATINGIP,
                    'status': n_const.PORT_STATUS_NOTAPPLICABLE,
                    'name': ''}
            if fip.get('floating_ip_address'):
                port['fixed_ips'] = [
                    {'ip_address': fip['floating_ip_address']}]

            if fip.get('subnet_id'):
                port['fixed_ips'] = [
                    {'subnet_id': fip['subnet_id']}]

            # 'status' in port dict could not be updated by default, use
            # check_allow_post to stop the verification of system
            external_port = p_utils.create_port(self._core_plugin,
                                                context.elevated(),
                                                {'port': port},
                                                check_allow_post=False)
            # Ensure IP addresses are allocated on external port
            # preferring IPv4 over IPv6 ones
            external_ips = self._port_ipv4_fixed_ips(external_port)
            if not external_ips:
                external_ips = self._port_ipv6_fixed_ips(external_port)
                if not external_ips:
                    self._core_plugin.delete_port(context, external_port['id'])
                    raise n_exc.ExternalIpAddressExhausted(net_id=f_net_id)

            floating_fixed_ip = external_ips[0]
            floating_ip_address = floating_fixed_ip['ip_address']
            floatingip_db = l3_db.FloatingIP(
                id=fip_id,
                tenant_id=fip['tenant_id'],
                status=initial_status,
                floating_network_id=fip['floating_network_id'],
                floating_ip_address=floating_ip_address,
                floating_port_id=external_port['id'],
                description=fip.get('description'))
            # Update association with internal port
            # and define external IP address
            self._update_fip_assoc(context, fip,
                                   floatingip_db, external_port)
            context.session.add(floatingip_db)
            floatingip_dict = self._make_floatingip_dict(
                floatingip_db, process_extensions=False)
            if dns_integration:
                dns_data = self._process_dns_floatingip_create_precommit(
                    context, floatingip_dict, fip)

        if dns_integration:
            self._process_dns_floatingip_create_postcommit(context,
                                                           floatingip_dict,
                                                           dns_data)
        self._apply_dict_extend_functions(l3.FLOATINGIPS, floatingip_dict,
                                          floatingip_db)
        return floatingip_dict
