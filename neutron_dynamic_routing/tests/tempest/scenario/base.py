# Copyright (C) 2015 VA Linux Systems Japan K.K.
# Copyright (C) 2015 Fumihiko Kakuma <kakuma at valinux co jp>
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

import collections
import time

import netaddr
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.tempest.api import base

from neutron_dynamic_routing.tests.common import container_base as ctn_base
from neutron_dynamic_routing.tests.common import quagga
from neutron_dynamic_routing.tests.tempest import bgp_client

CONF = config.CONF


def _setup_client_args(auth_provider):
    """Set up ServiceClient arguments using config settings. """
    service = CONF.network.catalog_type or 'network'
    region = CONF.network.region or 'regionOne'
    endpoint_type = CONF.network.endpoint_type
    build_interval = CONF.network.build_interval
    build_timeout = CONF.network.build_timeout

    # The disable_ssl appears in identity
    disable_ssl_certificate_validation = (
        CONF.identity.disable_ssl_certificate_validation)
    ca_certs = None

    # Trace in debug section
    trace_requests = CONF.debug.trace_requests

    return [auth_provider, service, region, endpoint_type,
            build_interval, build_timeout,
            disable_ssl_certificate_validation, ca_certs,
            trace_requests]


class BgpSpeakerTestJSONBase(base.BaseAdminNetworkTest):

    checktime = 120
    public_gw = '172.24.6.1'
    Net = collections.namedtuple('Net', 'net, mask, cidr, rip')
    PNet = Net(net='172.24.6.0', mask=24, cidr='172.24.6.0/24', rip=None)
    TNet = Net(net='10.10.0.0', mask=28, cidr='10.10.0.0/28', rip=None)
    AS = collections.namedtuple('AS', 'asn, router_id, adv_net')
    L_AS = AS(asn='64512', router_id='192.168.0.1', adv_net='10.10.0.0/24')
    R_AS = AS(asn='64522', router_id='192.168.0.2',
              adv_net='192.168.160.0/24')

    default_bgp_speaker_args = {'local_as': L_AS.asn,
                                'ip_version': 4,
                                'name': 'my-bgp-speaker',
                                'advertise_floating_ip_host_routes': True,
                                'advertise_tenant_networks': True}
    default_bgp_peer_args = {'remote_as': R_AS.asn,
                             'name': 'my-bgp-peer',
                             'peer_ip': None,
                             'auth_type': 'none'}

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(BgpSpeakerTestJSONBase, self).setUp()

    @classmethod
    def _setup_bgp_non_admin_client(cls):
        mgr = cls.get_client_manager()
        auth_provider = mgr.auth_provider
        client_args = _setup_client_args(auth_provider)
        cls.bgp_client = bgp_client.BgpSpeakerClientJSON(*client_args)

    @classmethod
    def _setup_bgp_admin_client(cls):
        mgr = cls.get_client_manager(credential_type='admin')
        auth_provider = mgr.auth_provider
        client_args = _setup_client_args(auth_provider)
        cls.bgp_adm_client = bgp_client.BgpSpeakerClientJSON(*client_args)

    @classmethod
    def resource_setup(cls):
        super(BgpSpeakerTestJSONBase, cls).resource_setup()
        if not test.is_extension_enabled('bgp_speaker', 'network'):
            msg = "BGP Speaker extension is not enabled."
            raise cls.skipException(msg)

        cls.brex = ctn_base.Bridge(name='br-ex',
                                   subnet=cls.PNet.cidr,
                                   start_ip='172.24.6.128',
                                   end_ip='172.24.6.254',
                                   exist=True, self_ip=True,
                                   fixed_ip=cls.public_gw + '/24')
        # This is dummy container object which keep data passes to
        # quagga container.
        cls.dr = ctn_base.BGPContainer(name='dr', asn=int(cls.L_AS.asn),
                                       router_id=cls.L_AS.router_id)
        cls.dr.set_ip_addr_manual(bridge='br-ex', ipv4=cls.public_gw)
        cls.dr.add_route(cls.L_AS.adv_net)
        # quagga container
        dockerimg = ctn_base.DockerImage()
        cls.q_img = dockerimg.create_quagga_image()
        cls.q1 = quagga.QuaggaBGPContainer(name='q1', asn=int(cls.R_AS.asn),
                                           router_id=cls.R_AS.router_id,
                                           ctn_image_name=cls.q_img)
        cls.q1.add_route(cls.R_AS.adv_net)
        waite_time = cls.q1.run()
        time.sleep(waite_time)
        cls.quagga_ip = cls.brex.addif(cls.q1)
        cls.q1.add_peer(cls.dr, bridge=cls.brex.name)

        cls.admin_routerports = []
        cls.admin_floatingips = []
        cls.admin_routers = []
        cls.ext_net_id = CONF.network.public_network_id
        cls._setup_bgp_admin_client()
        cls._setup_bgp_non_admin_client()

    @classmethod
    def resource_cleanup(cls):
        for floatingip in cls.admin_floatingips:
            cls._try_delete_resource(cls.admin_client.delete_floatingip,
                                     floatingip['id'])
        for routerport in cls.admin_routerports:
            cls._try_delete_resource(
                cls.admin_client.remove_router_interface_with_subnet_id,
                routerport['router_id'], routerport['subnet_id'])
        for router in cls.admin_routers:
            cls._try_delete_resource(cls.admin_client.delete_router,
                                     router['id'])
        super(BgpSpeakerTestJSONBase, cls).resource_cleanup()

    def create_bgp_speaker(self, auto_delete=True, **args):
        data = {'bgp_speaker': args}
        bgp_speaker = self.bgp_adm_client.create_bgp_speaker(data)
        bgp_speaker_id = bgp_speaker['bgp_speaker']['id']
        if auto_delete:
            self.addCleanup(self.bgp_adm_client.delete_bgp_speaker,
                            bgp_speaker_id)
        return bgp_speaker['bgp_speaker']

    def create_bgp_peer(self, **args):
        bgp_peer = self.bgp_adm_client.create_bgp_peer({'bgp_peer': args})
        bgp_peer_id = bgp_peer['bgp_peer']['id']
        self.addCleanup(self.bgp_adm_client.delete_bgp_peer, bgp_peer_id)
        return bgp_peer['bgp_peer']

    def get_dr_agent_id(self):
        agents = self.admin_client.list_agents(
            agent_type="BGP dynamic routing agent")
        self.assertTrue(agents['agents'][0]['alive'])
        return agents['agents'][0]['id']

    def add_bgp_speaker_to_dragent(self, agent_id, speaker_id):
        self.bgp_adm_client.add_bgp_speaker_to_dragent(agent_id, speaker_id)

    def create_bgp_network(self):
        addr_scope = self.create_address_scope('my-scope', ip_version=4)
        # external network
        ext_net = self.create_shared_network(**{'router:external': True})
        ext_subnetpool = self.create_subnetpool(
            'test-pool-ext',
            is_admin=True,
            default_prefixlen=self.PNet.mask,
            address_scope_id=addr_scope['id'],
            prefixes=[self.PNet.net + '/8'])
        ext_subnet = self.create_subnet(
            {'id': ext_net['id']},
            cidr=netaddr.IPNetwork(self.PNet.cidr),
            mask_bits=self.PNet.mask,
            ip_version=4,
            client=self.admin_client,
            subnetpool_id=ext_subnetpool['id'])
        gateway_ip = ext_subnet['gateway_ip']
        # tenant network
        tenant_net = self.create_network()
        tenant_subnetpool = self.create_subnetpool(
            'tenant-test-pool',
            default_prefixlen=24,
            address_scope_id=addr_scope['id'],
            prefixes=[self.TNet.net + '/16'])
        tenant_subnet = self.create_subnet(
            {'id': tenant_net['id']},
            cidr=netaddr.IPNetwork(self.TNet.cidr),
            mask_bits=self.TNet.mask,
            ip_version=4,
            subnetpool_id=tenant_subnetpool['id'])
        # router
        ext_gw_info = {'network_id': ext_net['id']}
        router_cr = self.admin_client.create_router(
            'my-router',
            external_gateway_info=ext_gw_info,
            distributed=False)['router']
        self.admin_routers.append(router_cr)
        self.admin_client.add_router_interface_with_subnet_id(
            router_cr['id'],
            tenant_subnet['id'])
        self.admin_routerports.append({'router_id': router_cr['id'],
                                       'subnet_id': tenant_subnet['id']})
        router = self.admin_client.show_router(router_cr['id'])['router']
        fixed_ips = router['external_gateway_info']['external_fixed_ips']
        self.router_pub_ip = fixed_ips[0]['ip_address']
        # speaker
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['id']
        self.bgp_adm_client.add_bgp_gateway_network(bgp_speaker_id,
                                                    ext_net['id'])
        self.default_bgp_peer_args['peer_ip'] = self.quagga_ip.split('/')[0]
        bgp_peer = self.create_bgp_peer(**self.default_bgp_peer_args)
        bgp_speaker_id = bgp_speaker['id']
        bgp_peer_id = bgp_peer['id']
        self.bgp_adm_client.add_bgp_peer_with_id(bgp_speaker_id,
                                                 bgp_peer_id)
        return (bgp_speaker_id, bgp_peer_id)
