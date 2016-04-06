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

from midonet.neutron.common import constants as midonet_const
from midonet.neutron.common import exceptions as midonet_exc
from neutron.callbacks import events
from neutron.callbacks import exceptions as callback_exc
from neutron.callbacks import registry
from neutron.callbacks import resources
from oslo_utils import excutils


def check_delete_network_precommit(context, id):
    try:
        kwargs = {'context': context, 'network_id': id}
        registry.notify(midonet_const.MIDONET_NETWORK,
                        midonet_const.PRECOMMIT_DELETE, None, **kwargs)
    except callback_exc.CallbackFailure as e:
        with excutils.save_and_reraise_exception():
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise midonet_exc.MidonetNetworkInUse(network_id=id, reason=e)

# To pass parameter validation in neutron.callbacks.manager, add MidoNet
# specific parameter here.
if midonet_const.PRECOMMIT_DELETE not in events.VALID:
    events.VALID = events.VALID + (midonet_const.PRECOMMIT_DELETE,)
if midonet_const.MIDONET_NETWORK not in resources.VALID:
    resources.VALID = resources.VALID + (midonet_const.MIDONET_NETWORK,)
registry.clear()
