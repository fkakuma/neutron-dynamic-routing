# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# This is based on the following
#     https://github.com/osrg/gobgp/test/lib/base.py
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import time
import itertools

from fabric.api import local
from fabric.api import lcd
from fabric.state import env
from fabric.state import output
from docker import Client
import netaddr

LOG = logging.getLogger(__name__)

DEFAULT_TEST_PREFIX = ''
DEFAULT_TEST_BASE_DIR = '/tmp/bgpcontainer'
TEST_PREFIX = DEFAULT_TEST_PREFIX
TEST_BASE_DIR = DEFAULT_TEST_BASE_DIR

BGP_FSM_IDLE = 'BGP_FSM_IDLE'
BGP_FSM_ACTIVE = 'BGP_FSM_ACTIVE'
BGP_FSM_ESTABLISHED = 'BGP_FSM_ESTABLISHED'

BGP_ATTR_TYPE_ORIGIN = 1
BGP_ATTR_TYPE_AS_PATH = 2
BGP_ATTR_TYPE_NEXT_HOP = 3
BGP_ATTR_TYPE_MULTI_EXIT_DISC = 4
BGP_ATTR_TYPE_LOCAL_PREF = 5
BGP_ATTR_TYPE_COMMUNITIES = 8
BGP_ATTR_TYPE_ORIGINATOR_ID = 9
BGP_ATTR_TYPE_CLUSTER_LIST = 10
BGP_ATTR_TYPE_MP_REACH_NLRI = 14
BGP_ATTR_TYPE_EXTENDED_COMMUNITIES = 16

env.abort_exception = RuntimeError
output.stderr = False


def try_several_times(f, t=3, s=1):
    e = None
    for i in range(t):
        try:
            r = f()
        except RuntimeError as e:
            time.sleep(s)
        else:
            return r
    raise e


def get_bridges():
    return try_several_times(lambda: local(
        "brctl show | awk 'NR > 1{print $1}'", capture=True)).split('\n')


def get_containers():
    return try_several_times(lambda: local(
        "docker ps -a | awk 'NR > 1 {print $NF}'", capture=True)).split('\n')


class CmdBuffer(list):
    def __init__(self, delim='\n'):
        super(CmdBuffer, self).__init__()
        self.delim = delim

    def __lshift__(self, value):
        self.append(value)

    def __str__(self):
        return self.delim.join(self)


class DockerImage(object):
    def __init__(self, baseimage='ubuntu:14.04.4'):
        self.baseimage = baseimage

    def create_quagga_image(self, tagname='quagga'):
        workdir = TEST_BASE_DIR + '/' + tagname
        pkges = 'quagga telnet tcpdump'
        c = CmdBuffer()
        c << 'FROM ' + self.baseimage
        c << 'RUN apt-get update'
        c << 'RUN apt-get install -qy --no-install-recommends ' + pkges
        c << 'CMD /usr/lib/quagga/bgpd'

        local('mkdir -p {0}'.format(workdir))
        with lcd(workdir):
            local('echo \'{0}\' > Dockerfile'.format(str(c)))
            self.build_image(tagname, workdir)
            local('rm -rf ' + workdir)
        return tagname

    def build_image(self, tagname, dockerfile_dir):
        local("docker build -t {0} {1}".format(tagname, dockerfile_dir))


class Bridge(object):
    def __init__(self, name, subnet='', start_ip=None, end_ip=None,
                 with_ip=True, self_ip=False,
                 fixed_ip=None, reuse=False):
        self.name = name
        if TEST_PREFIX != '':
            self.name = '{0}_{1}'.format(TEST_PREFIX, name)
        self.with_ip = with_ip
        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)
            if start_ip:
                self.start_ip = start_ip
            else:
                self.start_ip = netaddr.IPAddress(self.subnet.first)
            if end_ip:
                self.end_ip = end_ip
            else:
                self.end_ip = netaddr.IPAddress(self.subnet.last)

            def f():
                for host in netaddr.IPRange(self.start_ip, self.end_ip):
                    yield host
            self._ip_generator = f()
            # throw away first network address
            self.next_ip_address()

        if not reuse:
            def f():
                if self.name in get_bridges():
                    self.delete()
                local("ip link add {0} type bridge".format(self.name))
            try_several_times(f)
        try_several_times(lambda: local(
            "ip link set up dev {0}".format(self.name)))

        self.self_ip = self_ip
        if self_ip:
            if fixed_ip:
                self.ip_addr = fixed_ip
            else:
                self.ip_addr = self.next_ip_address()
            ips = self.check_br_addr(self.name)
            for key, ip in ips.items():
                if self.subnet.version == key:
                    try_several_times(lambda: local(
                        "ip addr del {0} dev {1}".format(
                            ip, self.name)))
            try_several_times(lambda: local(
                "ip addr add {0} dev {1}".format(self.ip_addr, self.name)))
        self.ctns = []

    def check_br_addr(self, br):
        ips = {}
        cmd = "ip a show dev %s" % br
        for line in local(cmd, capture=True).split('\n'):
            if line.strip().startswith("inet "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ips[4] = elems[1]
            elif line.strip().startswith("inet6 "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ips[6] = elems[1]
        return ips

    def next_ip_address(self):
        return "{0}/{1}".format(next(self._ip_generator),
                                self.subnet.prefixlen)

    def addif(self, ctn):
        name = ctn.next_if_name()
        self.ctns.append(ctn)
        ip_address = None
        if self.with_ip:
            ip_address = self.next_ip_address()
            ctn.pipework(self, ip_address, name)
        else:
            ctn.pipework(self, '0/0', name)
        return ip_address

    def delete(self):
        try_several_times(lambda: local(
            "ip link set down dev {0}".format(self.name)))
        try_several_times(lambda: local(
            "ip link delete {0} type bridge".format(self.name)))


class Container(object):
    def __init__(self, name, image=None):
        self.name = name
        self.image = image
        self.shared_volumes = []
        self.ip_addrs = []
        self.ip6_addrs = []
        self.is_running = False
        self.eths = []
        self.id = None

        if self.docker_name() in get_containers():
            self.remove()

    def docker_name(self):
        if TEST_PREFIX == DEFAULT_TEST_PREFIX:
            return self.name
        return '{0}_{1}'.format(TEST_PREFIX, self.name)

    def next_if_name(self):
        name = 'eth{0}'.format(len(self.eths) + 1)
        self.eths.append(name)
        return name

    def set_addr_info(self, bridge, ipv4=None, ipv6=None, ifname='eth0'):
        if ipv4:
            self.ip_addrs.append((ifname, ipv4, bridge))
        if ipv6:
            self.ip6_addrs.append((ifname, ipv6, bridge))

    def get_ip_addrs(self, bridge, ipv=4):
        ips = []
        if ipv == 4:
            ip_addrs = self.ip_addrs
        elif ipv == 6:
            ip_addrs = self.ip6_addrs
        else:
            return None
        for addrs in ip_addrs:
            if addrs[2] == bridge:
                ips.append(addrs[1])
        return ips

    def run(self):
        c = CmdBuffer(' ')
        c << "docker run --privileged=true"
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        c << "--name {0} --hostname {0} -id {1}".format(self.docker_name(),
                                                        self.image)
        self.id = try_several_times(lambda: local(str(c), capture=True))
        self.is_running = True
        self.local("ip li set up dev lo")
        ipv4 = None
        ipv6 = None
        for line in self.local("ip a show dev eth0", capture=True).split('\n'):
            if line.strip().startswith("inet "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ipv4 = elems[1]
            elif line.strip().startswith("inet6 "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ipv6 = elems[1]
        self.set_addr_info(bridge='docker0', ipv4=ipv4, ipv6=ipv6,
                           ifname='eth0')
        return 0

    def stop(self):
        ret = None
        if self.id:
            ctn_id = self.id
        else:
            ctn_id = self.docker_name()
        for i in range(3):
            if self.exist():
                try:
                    ret = local(
                        "docker stop -t 0 " + ctn_id, capture=True)
                    self.is_running = False
                    return ret
                except RuntimeError as e:
                    ret = e
                    time.sleep(1)
                else:
                    return ret
            else:
                return ret
        return ret

    def remove(self):
        ret = None
        if self.id:
            ctn_id = self.id
        else:
            ctn_id = self.docker_name()
        for i in range(3):
            if self.exist(all=True):
                try:
                    ret = local(
                        "docker rm -f " + ctn_id, capture=True)
                    self.is_running = False
                    return ret
                except RuntimeError as e:
                    ret = e
                    time.sleep(1)
                else:
                    return ret
            else:
                return ret
        return ret

    def exist(self, all=False):
        if self.id:
            ctn_id = self.id
        else:
            ctn_id = self.docker_name()
        cmd = 'docker ps --no-trunc=true'
        if all:
            cmd += ' --all=true'
        ret = local(cmd, capture=True)
        if ctn_id in ret:
            return True
        else:
            return False

    def pipework(self, bridge, ip_addr, intf_name=""):
        if not self.is_running:
            LOG.warning('Call run() before pipeworking')
            return
        c = CmdBuffer(' ')
        c << "pipework {0}".format(bridge.name)

        if intf_name != "":
            c << "-i {0}".format(intf_name)
        else:
            intf_name = "eth1"
        c << "{0} {1}".format(self.docker_name(), ip_addr)
        self.set_addr_info(bridge=bridge.name, ipv4=ip_addr, ifname=intf_name)
        try_several_times(lambda: local(str(c)))

    def local(self, cmd, capture=False, stream=False, detach=False):
        if stream:
            dckr = Client(timeout=120, version='auto')
            i = dckr.exec_create(container=self.docker_name(), cmd=cmd)
            return dckr.exec_start(i['Id'], tty=True,
                                   stream=stream, detach=detach)
        else:
            flag = '-d' if detach else ''
            return local('docker exec {0} {1} {2}'.format(
                flag, self.docker_name(), cmd), capture)

    def get_pid(self):
        if self.is_running:
            cmd = "docker inspect -f '{{.State.Pid}}' " + self.docker_name()
            return int(local(cmd, capture=True))
        return -1

    def start_tcpdump(self, interface=None, filename=None):
        if not interface:
            interface = "eth0"
        if not filename:
            filename = "{0}/{1}.dump".format(
                self.shared_volumes[0][1], interface)
        self.local(
            "tcpdump -i {0} -w {1}".format(interface, filename), detach=True)


class BGPContainer(Container):

    WAIT_FOR_BOOT = 1
    RETRY_INTERVAL = 5

    def __init__(self, name, asn, router_id, ctn_image_name=None):
        self.config_dir = TEST_BASE_DIR
        if TEST_PREFIX:
            self.config_dir += '/' + TEST_PREFIX
        self.config_dir += '/' + name
        local('if [ -e {0} ]; then rm -r {0}; fi'.format(self.config_dir))
        local('mkdir -p {0}'.format(self.config_dir))
        local('chmod 777 {0}'.format(self.config_dir))
        self.asn = asn
        self.router_id = router_id
        self.peers = {}
        self.routes = {}
        self.policies = {}
        super(BGPContainer, self).__init__(name, ctn_image_name)

    def __repr__(self):
        return str({'name': self.name, 'asn': self.asn,
                    'router_id': self.router_id})

    def run(self):
        self.create_config()
        super(BGPContainer, self).run()
        return self.WAIT_FOR_BOOT

    def add_peer(self, peer, passwd=None, vpn=False, is_rs_client=False,
                 policies=None, passive=False,
                 is_rr_client=False, cluster_id=None,
                 flowspec=False, bridge='', reload_config=True, as2=False,
                 graceful_restart=None, local_as=None, prefix_limit=None,
                 v6=False):
        neigh_addr = ''
        local_addr = ''
        it = itertools.product(self.ip_addrs, peer.ip_addrs)
        if v6:
            it = itertools.product(self.ip6_addrs, peer.ip6_addrs)

        for me, you in it:
            if bridge != '' and bridge != me[2]:
                continue
            if me[2] == you[2]:
                neigh_addr = you[1]
                local_addr = me[1]
                if v6:
                    addr, mask = local_addr.split('/')
                    local_addr = "{0}%{1}/{2}".format(addr, me[0], mask)
                break

        if neigh_addr == '':
            raise Exception('peer {0} seems not ip reachable'.format(peer))

        if not policies:
            policies = {}

        self.peers[peer] = {'neigh_addr': neigh_addr,
                            'passwd': passwd,
                            'vpn': vpn,
                            'flowspec': flowspec,
                            'is_rs_client': is_rs_client,
                            'is_rr_client': is_rr_client,
                            'cluster_id': cluster_id,
                            'policies': policies,
                            'passive': passive,
                            'local_addr': local_addr,
                            'as2': as2,
                            'graceful_restart': graceful_restart,
                            'local_as': local_as,
                            'prefix_limit': prefix_limit}
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def del_peer(self, peer, reload_config=True):
        del self.peers[peer]
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def disable_peer(self, peer):
        raise Exception('implement disable_peer() method')

    def enable_peer(self, peer):
        raise Exception('implement enable_peer() method')

    def log(self):
        return local('cat {0}/*.log'.format(self.config_dir), capture=True)

    def add_route(self, route, rf='ipv4', attribute=None, aspath=None,
                  community=None, med=None, extendedcommunity=None,
                  nexthop=None, matchs=None, thens=None,
                  local_pref=None, reload_config=True):
        self.routes[route] = {'prefix': route,
                              'rf': rf,
                              'attr': attribute,
                              'next-hop': nexthop,
                              'as-path': aspath,
                              'community': community,
                              'med': med,
                              'local-pref': local_pref,
                              'extended-community': extendedcommunity,
                              'matchs': matchs,
                              'thens': thens}
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def add_policy(self, policy, peer, typ, default='accept',
                   reload_config=True):
        self.set_default_policy(peer, typ, default)
        self.define_policy(policy)
        self.assign_policy(peer, policy, typ)
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def set_default_policy(self, peer, typ, default):
        if (typ in ['in', 'out', 'import', 'export'] and
                default in ['reject', 'accept']):
            if 'default-policy' not in self.peers[peer]:
                self.peers[peer]['default-policy'] = {}
            self.peers[peer]['default-policy'][typ] = default
        else:
            raise Exception('wrong type or default')

    def define_policy(self, policy):
        self.policies[policy['name']] = policy

    def assign_policy(self, peer, policy, typ):
        if peer not in self.peers:
            raise Exception('peer {0} not found'.format(peer.name))
        name = policy['name']
        if name not in self.policies:
            raise Exception('policy {0} not found'.format(name))
        self.peers[peer]['policies'][typ] = policy

    def get_local_rib(self, peer, rf):
        raise Exception('implement get_local_rib() method')

    def get_global_rib(self, rf):
        raise Exception('implement get_global_rib() method')

    def get_neighbor_state(self, peer_id):
        raise Exception('implement get_neighbor() method')

    def get_reachablily(self, prefix, timeout=20):
            version = netaddr.IPNetwork(prefix).version
            addr = prefix.split('/')[0]
            if version == 4:
                ping_cmd = 'ping'
            elif version == 6:
                ping_cmd = 'ping6'
            else:
                raise Exception(
                    'unsupported route family: {0}'.format(version))
            cmd = '/bin/bash -c "/bin/{0} -c 1 -w 1 {1} | xargs echo"'.format(
                ping_cmd, addr)
            interval = 1
            count = 0
            while True:
                res = self.local(cmd, capture=True)
                LOG.info(res)
                if '1 packets received' in res and '0% packet loss':
                    break
                time.sleep(interval)
                count += interval
                if count >= timeout:
                    raise Exception('timeout')
            return True

    def wait_for(self, expected_state, peer, timeout=120):
        interval = 1
        count = 0
        while True:
            state = self.get_neighbor_state(peer)
            LOG.info("{0}'s peer {1} state: {2}".format(self.router_id,
                                                        peer.router_id,
                                                        state))
            if state == expected_state:
                return

            time.sleep(interval)
            count += interval
            if count >= timeout:
                raise Exception('timeout')

    def add_static_route(self, network, next_hop):
        cmd = '/sbin/ip route add {0} via {1}'.format(network, next_hop)
        self.local(cmd)

    def set_ipv6_forward(self):
        cmd = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        self.local(cmd)

    def create_config(self):
        raise Exception('implement create_config() method')

    def reload_config(self):
        raise Exception('implement reload_config() method')
