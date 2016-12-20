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

    RAS_MAX = 3
    public_gw = '2001:db8::1'
    MyScope = base.Scope(name='my-scope')
    PNet = base.Net(name='', net='2001:db8::', mask=64,
                    cidr='2001:db8::/64', router=None)
    PPool = base.Pool(name='test-pool-ext', prefixlen=PNet.mask,
                      prefixes=[PNet.net + '/8'])
    PSubNet = base.SubNet(name='', cidr=PNet.cidr, mask=PNet.mask)
    TNet = base.Net(name='', net='2001:db8:8000::', mask=64,
                    cidr='2001:db8:8000::/64', router=None)
    TPool = base.Pool(name='tenant-test-pool', prefixlen=TNet.mask,
                      prefixes=[TNet.net + '/48'])
    TSubNet = base.SubNet(name='', cidr=TNet.cidr, mask=TNet.mask)
    MyRouter = base.Router(name='my-router', gw='', dist=False)
    L_AS = base.AS(asn='64512', router_id='192.168.0.1', adv_net=TNet.cidr)
    ras_l = [
        base.AS(asn='64522', router_id='192.168.0.12',
                adv_net='2001:db8:9002::/48'),
        base.AS(asn='64523', router_id='192.168.0.13',
                adv_net='2001:db8:9003::/48'),
        base.AS(asn='64524', router_id='192.168.0.14',
                adv_net='2001:db8:9004::/48')
    ]

    bgp_speaker_args = {
        'local_as': L_AS.asn,
        'ip_version': 6,
        'name': 'my-bgp-speaker1',
        'advertise_floating_ip_host_routes': True,
        'advertise_tenant_networks': True
    }
    bgp_peer_args = [
        {'remote_as': ras_l[0].asn,
         'name': 'my-bgp-peer1',
         'peer_ip': None,
         'auth_type': 'none'},
        {'remote_as': ras_l[1].asn,
         'name': 'my-bgp-peer2',
         'peer_ip': None,
         'auth_type': 'none'},
        {'remote_as': ras_l[2].asn,
         'name': 'my-bgp-peer3',
         'peer_ip': None,
         'auth_type': 'none'}
    ]

    def setUp(self):
        super(BgpSpeakerTestJSONBase, self).setUp()

    @classmethod
    def resource_setup_container(cls):
        cls.brex = ctn_base.Bridge(name='br-ex',
                                   subnet=cls.PNet.cidr,
                                   start_ip='2001:db8::8000',
                                   end_ip='2001:db8::fffe',
                                   self_ip=True,
                                   fixed_ip=cls.public_gw + '/64',
                                   br_type=ctn_base.BRIDGE_TYPE_OVS)
        cls.bridges.append(cls.brex)
        # This is dummy container object for a dr service.
        # This keeps data which passes to a quagga container.
        cls.dr = ctn_base.BGPContainer(name='dr', asn=int(cls.L_AS.asn),
                                       router_id=cls.L_AS.router_id)
        cls.dr.set_addr_info(bridge='br-ex', ipv6=cls.public_gw)
        # quagga container
        cls.dockerimg = ctn_base.DockerImage()
        cls.q_img = cls.dockerimg.create_quagga(check_exist=True)
        cls.images.append(cls.q_img)
        for i in range(cls.RAS_MAX):
            qg = quagga.QuaggaBGPContainer(name='q' + str(i + 1),
                                           asn=int(cls.ras_l[i].asn),
                                           router_id=cls.ras_l[i].router_id,
                                           ctn_image_name=cls.q_img)
            cls.containers.append(qg)
            cls.rass.append(qg)
            qg.add_route(cls.ras_l[i].adv_net, route_info={'rf': 'ipv6'})
            qg.run(wait=True)
            cls.ras_ip.append(cls.brex.addif(qg))
            qg.add_peer(cls.dr, bridge=cls.brex.name, v6=True)
