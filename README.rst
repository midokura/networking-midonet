==================
networking-midonet
==================

This is the official Midonet Neutron plugin.


How to Install
--------------

Run the following command to install the plugin in the system:

::

    $ sudo python setup.py install


The following entry in ``neutron.conf`` enables MidoNet as the Neutron plugin.
There are two Kilo plugins to choose from.

Kilo plugin v1, which is compatible with MidoNet v2015.03 and v2015.06:

::
    core_plugin = neutron.plugins.midonet.plugin.MidonetPluginV2


Kilo plugin v2, which is compatible with MidoNet v2015.09 and beyond:

::
    core_plugin = midonet.neutron.plugin_v2.MidonetPluginV2


LBaaS
-----

Starting in Kilo, MidoNet plugin implements LBaaS v1 following the advanced
service driver model.  To configure MidoNet as the LBaaS driver, set the
following entries in the Neutron configuration file
(/etc/neutron/neutron.conf):

::
    [DEFAULT]
    service_plugins = lbaas

    [service_providers]
    service_provider=LOADBALANCER:Midonet:midonet.neutron.services.loadbalancer.driver.MidonetLoadbalancerDriver:default


VPNaaS
------

Starting v5.1, MidoNet implements Neutron VPNaaS extension API.

MidoNet plugin implements VPNaaS as a service driver.  To configure it,
add the following entries in the Neutron configuration file
``/etc/neutron/neutron.conf``::

    [DEFAULT]
    service_plugins = vpnaas

    [service_providers]
    service_provider=VPN:Midonet:midonet.neutron.services.vpn.service_drivers.midonet_ipsec.MidonetIPsecVPNDriver:default

NOTE: This plugin does not use Neutron VPNaaS agent.


RegionalSecurityGroup
---------------------

In Fujitsu Kilo, MidonetPlugin supports Fujitsu RegionalSecurityGroup.

There is a new plugin called "MidonetRegionalSGPlugin".
To configure it, add the following entries in ``/etc/neutron/neutron.conf``::

    [DEFAULT]
    core_plugin = midonet.neutron.plugin_rsg.MidonetRegionalSGPlugin

    # ========Start RegionalSecurityGroup Config Option=========
    sg_url = https://<host>:<port>/<path>
    # sg_http_timeout = 60
    # sync_sg_interval = 40
    # sync_sg_initial_delay = 5
    # ========End RegionalSecurityGroup Config Option===========

NOTE:

* ``sg_url`` : Specify URL of SG service.
* ``sg_http_timeout`` : Specify http timeout value.
* ``sync_sg_interval`` : Specify interval periodically to sync data.
* ``sync_sg_initial_delay`` : Specify initial delay of periodical sync.

BGP dynamic routing service
---------------------------

Starting v5.2, MidoNet implements Neutron BGP dynamic routing service extension API.
The implementation differs from upstream as follows:

- Router that is treated as bgp-speaker can be specified explicitly.
- Bgp-peer can relate to only one bgp-speaker.
- Binding network to bgp-speaker must be done before associating peers.
- Removing network from bgp-speaker must be done after all peers are
  disassociated from the bgp-speaker.
- Only one network can be associated with a bgp-speaker.
- Advertise_floating_ip_host_routes and advertise_tenant_networks are ignored.
- Attached network to the router and destination network in extra routes on the
  router are showed as advertised routes.

To configure it, add the following service plugin to the `service_plugins` list
in the DEFAULT section of ``/etc/neutron/neutron.conf``::

    midonet.neutron.services.bgp.plugin.MidonetBgpPlugin

Tests
-----

You can run the unit tests with the following command.::

    $ ./run_tests.sh -f -V

``run_tests.sh`` installs its requirements to ``.venv`` on the initial run.
``-f`` forces a clean re-build of the virtual environment. If you just make
changes on the working tree without any change on the dependencies, you can
ignore ``-f`` switch.

``-V`` or ``--virtual-env`` is specified to use virtualenv and this should be
always turned on.


To know more detail about command options, please execute it with ``---help``.::

    $ ./run_tests.sh --help


Creating Packages
-----------------

Run the following command to generate both both the RPM and Debian packages
with the provided version:
::

    $ ./package.sh some_version


HACKING
-------

To contribute to this repo, please go through the following steps.
