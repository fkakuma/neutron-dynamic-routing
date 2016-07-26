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

import time

from tempest import config
from tempest import test

from neutron_dynamic_routing.tests.tempest.scenario.ipv4 import base

from ryu.tests.integrated.common import docker_base as ctn_base

CONF = config.CONF


class BgpSpeakerBasicTest(base.BgpSpeakerTestJSONBase):

    @test.idempotent_id('7f2acbc2-ff88-4a63-aa02-a2f9feb3f5b0')
    def test_check_neighbor_established(self):
        self.default_bgp_peer_args['peer_ip'] = self.q1_ip.split('/')[0]
        speaker, peer = self.create_bgp_network(
            4, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter,
            self.default_bgp_speaker_args,
            self.default_bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)

    @test.idempotent_id('f32245fc-aeab-4244-acfa-3af9dd662e8d')
    def test_check_advertised_tenant_network(self):
        self.default_bgp_peer_args['peer_ip'] = self.q1_ip.split('/')[0]
        speaker, peer = self.create_bgp_network(
            4, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter,
            self.default_bgp_speaker_args,
            self.default_bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)
        rib = self.q1.get_global_rib(prefix=self.TNet.cidr)
        self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])
