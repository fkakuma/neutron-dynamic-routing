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

from neutron_dynamic_routing.tests.tempest.scenario.ipv6 import base

from ryu.tests.integrated.common import docker_base as ctn_base

CONF = config.CONF


class BgpSpeakerBasicTest(base.BgpSpeakerTestJSONBase):

    @test.idempotent_id('5194a8e2-95bd-49f0-872d-1e3e875ede32')
    def test_check_neighbor_established(self):
        self.bgp_peer_args[0]['peer_ip'] = self.ras_ip[0].split('/')[0]
        ext_net_id = self.create_bgp_network(
            6, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_bgp_speaker_and_peer(
            ext_net_id,
            self.bgp_speaker_args,
            [self.bgp_peer_args[0]])
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.rass[0].get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)

    @test.idempotent_id('6a3483fc-8c8a-4387-bda6-c7061410e04b')
    def test_check_advertised_tenant_network(self):
        self.bgp_peer_args[0]['peer_ip'] = self.ras_ip[0].split('/')[0]
        ext_net_id = self.create_bgp_network(
            6, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_bgp_speaker_and_peer(
            ext_net_id,
            self.bgp_speaker_args,
            [self.bgp_peer_args[0]])
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.rass[0].get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)
        rib = self.rass[0].get_global_rib(prefix=self.TNet.cidr, rf='ipv6')
        self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])

    @test.idempotent_id('f81012f3-2f7e-4b3c-8c1d-b1778146d712')
    def test_check_neighbor_established_with_multiple_peers(self):
        for i in range(0, self.RAS_MAX):
            self.bgp_peer_args[i]['peer_ip'] = self.ras_ip[i].split('/')[0]
        ext_net_id = self.create_bgp_network(
            6, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_bgp_speaker_and_peer(
            ext_net_id,
            self.bgp_speaker_args,
            self.bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        ras_list = []
        for i in range(0, self.RAS_MAX):
            ras_list.append({'as': self.rass[i], 'check': False})
        ok_ras = 0
        for i in range(0, self.checktime):
            for j in range(0, self.RAS_MAX):
                if ras_list[j]['check']:
                    continue
                neighbor_state = ras_list[j]['as'].get_neighbor_state(self.dr)
                if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                    ras_list[j]['check'] = True
                    ok_ras += 1
            if ok_ras == self.RAS_MAX:
                break
            time.sleep(1)
        self.assertEqual(ok_ras, self.RAS_MAX)

    @test.idempotent_id('be710ec1-a338-44c9-8b89-31c3532aae65')
    def test_check_advertised_tenant_network_with_multiple_peers(self):
        for i in range(0, self.RAS_MAX):
            self.bgp_peer_args[i]['peer_ip'] = self.ras_ip[i].split('/')[0]
        ext_net_id = self.create_bgp_network(
            6, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_bgp_speaker_and_peer(
            ext_net_id,
            self.bgp_speaker_args,
            self.bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        ras_list = []
        for i in range(0, self.RAS_MAX):
            ras_list.append({'as': self.rass[i], 'check': False})
        ok_ras = 0
        for i in range(0, self.checktime):
            for j in range(0, self.RAS_MAX):
                if ras_list[j]['check']:
                    continue
                neighbor_state = ras_list[j]['as'].get_neighbor_state(self.dr)
                if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                    ras_list[j]['check'] = True
                    ok_ras += 1
            if ok_ras == self.RAS_MAX:
                break
            time.sleep(1)
        self.assertEqual(ok_ras, self.RAS_MAX)
        for i in range(0, self.RAS_MAX):
            rib = self.rass[i].get_global_rib(prefix=self.TNet.cidr, rf='ipv6')
            self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])
