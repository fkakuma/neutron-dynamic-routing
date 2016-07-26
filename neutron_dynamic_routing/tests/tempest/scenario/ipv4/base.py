# Copyright (C) 2016 VA Linux Systems Japan K.K.
# Copyright (C) 2016 Fumihiko Kakuma <kakuma at valinux co jp>
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

from neutron_dynamic_routing.tests.tempest.scenario import base
from ryu.tests.integrated.common import docker_base as ctn_base
from ryu.tests.integrated.common import quagga


class BgpSpeakerTestJSONBase(base.BgpSpeakerScenarioTestJSONBase):

    public_gw = '172.24.6.1'
    MyScope = base.Scope(name='my-scope')
    PNet = base.Net(name='', net='172.24.6.0', mask=24,
                    cidr='172.24.6.0/24', router=None)
    PPool = base.Pool(name='test-pool-ext', prefixlen=PNet.mask,
                      prefixes=[PNet.net + '/8'])
    PSubNet = base.SubNet(name='', cidr=PNet.cidr, mask=PNet.mask)
    TNet = base.Net(name='', net='10.10.0.0', mask=28,
                    cidr='10.10.0.0/28', router=None)
    TPool = base.Pool(name='tenant-test-pool', prefixlen=TNet.mask,
                      prefixes=[TNet.net + '/16'])
    TSubNet = base.SubNet(name='', cidr=TNet.cidr, mask=TNet.mask)
    MyRouter = base.Router(name='my-router', gw='', dist=False)
    L_AS = base.AS(asn='64512', router_id='192.168.0.1', adv_net=TNet.cidr)
    R_AS = base.AS(asn='64522', router_id='192.168.0.2',
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
        super(BgpSpeakerTestJSONBase, self).setUp()

    @classmethod
    def resource_setup_container(cls):
        cls.brex = ctn_base.Bridge(name='br-ex',
                                   subnet=cls.PNet.cidr,
                                   start_ip='172.24.6.128',
                                   end_ip='172.24.6.254',
                                   self_ip=True,
                                   fixed_ip=cls.public_gw + '/24',
                                   br_type=ctn_base.BRIDGE_TYPE_OVS)
        cls.bridges.append(cls.brex)
        # This is dummy container object for a dr service.
        # This keeps data which passes to a quagga container.
        cls.dr = ctn_base.BGPContainer(name='dr', asn=int(cls.L_AS.asn),
                                       router_id=cls.L_AS.router_id)
        cls.dr.set_addr_info(bridge='br-ex', ipv4=cls.public_gw)
        # quagga container
        cls.dockerimg = ctn_base.DockerImage()
        cls.q_img = cls.dockerimg.create_quagga(check_exist=True)
        cls.images.append(cls.q_img)
        cls.q1 = quagga.QuaggaBGPContainer(name='q1', asn=int(cls.R_AS.asn),
                                           router_id=cls.R_AS.router_id,
                                           ctn_image_name=cls.q_img)
        cls.containers.append(cls.q1)
        cls.q1.add_route(cls.R_AS.adv_net)
        cls.q1.run(wait=True)
        cls.q1_ip = cls.brex.addif(cls.q1)
        cls.q1.add_peer(cls.dr, bridge=cls.brex.name)
