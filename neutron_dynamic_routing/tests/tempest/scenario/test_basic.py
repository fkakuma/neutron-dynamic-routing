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

import time

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron_dynamic_routing.tests.tempest.scenario import base
from neutron_dynamic_routing.tests.tempest import bgp_client

from neutron_dynamic_routing.tests.common import container_base as ctn_base

CONF = config.CONF


class BgpSpeakerBasicTest(base.BgpSpeakerTestJSONBase):

    @test.idempotent_id('7f2acbc2-ff88-4a63-aa02-a2f9feb3f5b0')
    def test_check_neighbor_established(self):
        speaker, peer = self.create_bgp_network()
        dr_agent_id = self.get_dr_agent_id()
        self.add_bgp_speaker_to_dragent(dr_agent_id, speaker)
        neighbor_state = None
        for i in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)

    @test.idempotent_id('f32245fc-aeab-4244-acfa-3af9dd662e8d')
    def test_check_advertised_tenant_network(self):
        speaker, peer = self.create_bgp_network()
        dr_agent_id = self.get_dr_agent_id()
        self.add_bgp_speaker_to_dragent(dr_agent_id, speaker)
        for i in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.dr)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)
        rib = self.q1.get_global_rib(prefix=self.TNet.cidr)
        self.assertEqual(self.router_pub_ip, rib[0]['nexthop'])
