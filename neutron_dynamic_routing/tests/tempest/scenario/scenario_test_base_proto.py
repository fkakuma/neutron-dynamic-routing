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

from neutron_dynamic_routing.tests.tempest.scenario import base

from ryu.tests.integrated.common import docker_base as ctn_base

CONF = config.CONF


class BgpSpeakerProtoTestBase(base.BgpSpeakerScenarioTestJSONBase):

    def _test_check_neighbor_established(self, ip_version):
        self.bgp_peer_args[0]['peer_ip'] = self.r_as_ip[0].split('/')[0]
        ext_net_id = self.create_bgp_network(
            ip_version, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_and_add_peers_to_speaker(
            ext_net_id,
            self.bgp_speaker_args,
            [self.bgp_peer_args[0]])
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.r_ass[0].get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)

    def _test_check_advertised_tenant_network(self, ip_version):
        self.bgp_peer_args[0]['peer_ip'] = self.r_as_ip[0].split('/')[0]
        ext_net_id = self.create_bgp_network(
            ip_version, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_and_add_peers_to_speaker(
            ext_net_id,
            self.bgp_speaker_args,
            [self.bgp_peer_args[0]])
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for i in range(0, self.checktime):
            neighbor_state = self.r_ass[0].get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)
        rf = 'ipv' + str(ip_version)
        rib = self.r_ass[0].get_global_rib(prefix=self.TNet.cidr, rf=rf)
        self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])

    def _test_check_neighbor_established_with_multiple_peers(
            self, ip_version):
        for i in range(0, self.RAS_MAX):
            self.bgp_peer_args[i]['peer_ip'] = self.r_as_ip[i].split('/')[0]
        ext_net_id = self.create_bgp_network(
            ip_version, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_and_add_peers_to_speaker(
            ext_net_id,
            self.bgp_speaker_args,
            self.bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        ras_list = []
        for i in range(0, self.RAS_MAX):
            ras_list.append({'as': self.r_ass[i], 'check': False})
        ok_ras = 0
        for i in range(0, self.checktime):
            for j in range(0, self.RAS_MAX):
                if ras_list[j]['check']:
                    continue
                neighbor_state = ras_list[j]['as'].get_neighbor_state(self.dr)
                if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                    ras_list[j]['check'] = True
                    ok_ras += 1
            if ok_ras >= self.RAS_MAX:
                break
            time.sleep(1)
        self.assertEqual(ok_ras, self.RAS_MAX)

    def _test_check_advertised_tenant_network_with_multiple_peers(
            self, ip_version):
        for i in range(0, self.RAS_MAX):
            self.bgp_peer_args[i]['peer_ip'] = self.r_as_ip[i].split('/')[0]
        ext_net_id = self.create_bgp_network(
            ip_version, self.MyScope,
            self.PNet, self.PPool, self.PSubNet,
            [[self.TNet, self.TPool, self.TSubNet]],
            self.MyRouter)
        speaker_id, peers_ids = self.create_and_add_peers_to_speaker(
            ext_net_id,
            self.bgp_speaker_args,
            self.bgp_peer_args)
        dragent_id = self.get_dragent_id()
        self.add_bgp_speaker_to_dragent(dragent_id, speaker_id)
        neighbor_state = ctn_base.BGP_FSM_IDLE
        ras_list = []
        for i in range(0, self.RAS_MAX):
            ras_list.append({'as': self.r_ass[i], 'check': False})
        ok_ras = 0
        for i in range(0, self.checktime):
            for j in range(0, self.RAS_MAX):
                if ras_list[j]['check']:
                    continue
                neighbor_state = ras_list[j]['as'].get_neighbor_state(self.dr)
                if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                    ras_list[j]['check'] = True
                    ok_ras += 1
            if ok_ras >= self.RAS_MAX:
                break
            time.sleep(1)
        self.assertEqual(ok_ras, self.RAS_MAX)
        rf = 'ipv' + str(ip_version)
        for i in range(0, self.RAS_MAX):
            rib = self.r_ass[i].get_global_rib(prefix=self.TNet.cidr, rf=rf)
            self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])
