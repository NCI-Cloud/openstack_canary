#!/usr/bin/python

'''
A Canary OpenStack instance, used to test basic OpenStack functionality.
'''

import os
import re
import ConfigParser
from paramiko.client import SSHClient
from paramiko import AutoAddPolicy
# from openstackclient.common import clientmanager
from keystoneclient import client as keystone_client
from novaclient import client as nova_client
import novaclient.exceptions as nova_exceptions
from cinderclient import client as cinder_client
import cinderclient.exceptions as cinder_exceptions
from neutronclient.v2_0 import client as neutron_client
from neutronclient.common.exceptions import Conflict, IpAddressInUseClient
import time
import logging
MODULE_LOGGER = logging.getLogger('openstack_canary.canary')


# FIXME: Obtain these from client libraries or Keystone catalog
NOVA_API_VERSIONS = ("3", "2", "1.1")
CINDER_API_VERSIONS = ("2", "1")


class Canary(object):
    '''
    A canary OpenStack instance.
    '''

    def __init__(self, params):
        self.params = params
        self.logger = logging.getLogger('openstack_canary.canary.Canary')
        self.floating_ip = None
        self.keystone = keystone_client.Client(
            username=params['username'],
            password=params['password'],
            project_name=params['tenant_name'],
            auth_url=params['auth_url']
        )
        self.keystone.authenticate()
        self.token = self.keystone.auth_ref['token']['id']
        # self.logger.debug("Got token: '%s'", self.token)
        self.nova = None
        for version in NOVA_API_VERSIONS:
            try:
                self.nova = nova_client.Client(
                    version,
                    params['username'],
                    params['password'],
                    params['tenant_name'],
                    params['auth_url']
                )
            except nova_exceptions.ClientException as exc:
                self.logger.debug(
                    "Failed to instantiate Nova client for API version '%s': %s",
                    version,
                    exc
                )
        if self.nova is None:
            raise nova_exceptions.UnsupportedVersion()
        self.cinder = None
        for version in CINDER_API_VERSIONS:
            try:
                self.cinder = cinder_client.Client(
                    version,
                    params['username'],
                    params['password'],
                    params['tenant_name'],
                    params['auth_url']
                )
            except cinder_exceptions.ClientException as exc:
                self.logger.debug(
                    "Failed to instantiate Cinder client for API version '%s': %s",
                    version,
                    exc
                )
        if self.cinder is None:
            raise cinder_exceptions.UnsupportedVersion()
        self.flavor = self.nova.flavors.find(name=params['flavour_name'])
        if 'volume_size' in params and params['volume_size'] and int(params['volume_size']) > 0:
            self.volume = self.cinder.volumes.create(
                availability_zone=params['availability_zone'],
                display_name=params['volume_name'],
                size=int(params['volume_size'])
            )
            self.logger.info(
                "Volume %s created",
                self.volume.id
            )
            bdm = dict({'/dev/vdz': self.volume.id})
        else:
            self.volume = None
            bdm = None
        if 'network_id' in params and params['network_id']:
            self.neutron = neutron_client.Client(
                username=params['username'],
                password=params['password'],
                tenant_name=params['tenant_name'],
                auth_url=params['auth_url']
            )
            nics = [dict({'net-id': params['network_id']})]
        else:
            self.neutron = None
            nics = None
        self.instance = self.nova.servers.create(
            name=params['instance_name'],
            image=params['image_id'],
            flavor=self.flavor,
            availability_zone=params['availability_zone'],
            block_device_mapping=bdm,
            nics=nics,
            userdata=params['user_data'],
            key_name=params['key_name'],
            security_groups=params['security_group_names'].split()
        )
        status = self.instance.status
        while status == 'BUILD':
            self.logger.debug(
                "Instance '%s' has status '%s', waiting %ds",
                self.instance.id,
                status,
                int(params['active_poll'])
            )
            time.sleep(int(params['active_poll']))
            self.instance = self.nova.servers.get(self.instance.id)
            status = self.instance.status
        if status == 'ERROR':
            self.logger.error(self.instance.diagnostics())
            raise nova_exceptions.InstanceInErrorState()
        if status != 'ACTIVE':
            self.logger.error(self.instance.diagnostics())
            raise nova_exceptions.ClientException(
                "Instance unexpectedly has status '%s'" % status
            )
        self.logger.info(
            "Instance '%s' has status '%s', waiting %ds for boot",
            self.instance.id,
            self.instance.status,
            int(params['boot_wait'])
        )
        time.sleep(int(params['boot_wait']))

    def _is_private(self, address):
        private_patterns = (
            r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
            r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
            r'^192\.168\.\d{1,3}$',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}$'
        )
        private_res = [re.compile(patt) for patt in private_patterns]
        for private_re in private_res:
            if private_re.match(address):
                return True
        return False

    def _is_public(self, address):
        return not self._is_private(address)

    def _iter_addrs(self):
        if self.floating_ip:
            yield ('floating', self.floating_ip['floating_ip_address'])
        for netname, addresslist in self.instance.networks.iteritems():
            for address in addresslist:
                yield (netname, address)

    def _iter_private_addrs(self):
        for netname, address in self._iter_addrs():
            if self._is_private(address):
                yield (netname, address)

    def _iter_public_addrs(self):
        for netname, address in self._iter_addrs():
            if self._is_public(address):
                yield (netname, address)

    def _iter_ports_of_private_ips(self):
        for (netname, address) in self._iter_private_addrs():
            ports = self.neutron.list_ports(
                retrieve_all=False,
                device_id=self.instance.id,
                fixed_ip_address=address
            )
            for port_group in ports:
                for port in port_group['ports']:
                    self.logger.debug('Port of private address: %s', port)
                    yield port

    def is_available_floating_ip(self, floatip):
        return (
            # Belongs to our tenant
            floatip['tenant_id'] == self.params['tenant_id'] and
            # Not already connected somewhere
            floatip['port_id'] is None
        )

    def find_free_floating_ip(self):
        floatips = self.neutron.list_floatingips(
            retrieve_all=False,
            tenant_id=self.params['tenant_id']
            # FIXME: Returns no results
            # , port_id=None
        )
        for floatip_chunk in floatips:
            for floatip in floatip_chunk['floatingips']:
                if self.is_available_floating_ip(floatip):
                    return floatip
        raise ValueError("No floating IPs available")

    def attach_floating_ip_to_port(self, floatip, port):
        self.neutron.update_floatingip(
            floatip['id'],
            dict({
                'floatingip': dict({
                    'port_id': port['id']
                })
            })
        )

    def attach_any_floating_ip_to_port(self, port):
        attempt_number = 0
        while attempt_number < 5:
            # Attempt to find a free floating IP
            floatip = self.find_free_floating_ip()
            # NOTE: Window of vulnerability here.
            # At this point, something else can begin using the float.
            try:
                self.attach_floating_ip_to_port(floatip, port)
                self.logger.debug(
                    'Attached float\n%s\nto port\n%s',
                    floatip,
                    port
                )
                self.floating_ip = floatip
                self.logger.debug(
                    'Waiting %ss for float to become usable',
                    int(self.params['floatip_wait'])
                )
                time.sleep(int(self.params['floatip_wait']))
                return
            except (Conflict, IpAddressInUseClient):
                # FIXME: What are the exception types possible when
                # the floating IP address is no longer available,
                # either nonexistent or already used?
                attempt_number += 1
        raise ValueError(
            "Gave up trying to attach a floating IP after " + (attempt_number + 1) + " attempts"
        )

    def attach_any_floating_ip_to_any_private_port(self):
        for port in self._iter_ports_of_private_ips():
            self.attach_any_floating_ip_to_port(port)
            return

    def make_internet_accessible(self):
        public_addrs = [addr for addr in self._iter_public_addrs()]
        if not public_addrs:
            if self.neutron:
                self.attach_any_floating_ip_to_any_private_port()
            else:
                raise ValueError(
                    "Instance has no public addresses by default, and Neutron support is disabled"
                )

    def test_ssh_cmd_output(self, client, command, pattern):
        regex = re.compile(pattern)
        stdin, stdout, stderr = client.exec_command(command)
        found_canary = False
        stdin.close()
        stdout_lines = [ line for line in stdout ]
        for line in stdout_lines:
            line = line.rstrip()
            if regex.match(line):
                found_canary = True
        if not found_canary:
            for line in stderr:
                line = line.rstrip()
                self.logger.debug('STDERR: ' + line)
            for line in stdout_lines:
                self.logger.debug('STDOUT: ' + line)
            raise ValueError("Expected output not found in test command")

    def test_ssh_echo(self, client):
        self.test_ssh_cmd_output(
            client,
            'echo CANARY_PAYLOAD',
            r'^CANARY_PAYLOAD$'
        )
        self.logger.info(
            "SSH echo test successful"
        )

    def test_ssh_ping_host(self, client, host):
        self.test_ssh_cmd_output(
            client,
            'ping -c 1 ' + host,
            r'[0-9]+ bytes from ' + host
        )
        self.logger.info(
            "SSH ping test successful"
        )

    def test_ssh_resolve_host(self, client, host):
        self.test_ssh_cmd_output(
            client,
            'host ' + host,
            r'^' + host + ' has (.* )?address'
        )
        self.logger.info(
            "SSH host resolution successful"
        )

    def test_ssh_address(self, netname, address):
        try:
            client = SSHClient()
            # client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(address, username=self.params['ssh_username'])
        except:
            self.logger.debug(self.instance.get_console_output(10))
            raise
        self.test_ssh_echo(client)
        if 'ssh_ping_target' in self.params and self.params['ssh_ping_target']:
            self.test_ssh_ping_host(client, self.params['ssh_ping_target'])
        if 'ssh_resolve_target' in self.params and self.params['ssh_resolve_target']:
            self.test_ssh_resolve_host(client, self.params['ssh_resolve_target'])

    def test_address(self, netname, address):
        self.logger.info(
            "Testing address '%s' on network '%s'",
            address,
            netname
        )
        self.test_ssh_address(netname, address)

    def test_public_addrs(self):
        self.make_internet_accessible()
        public_addrs = [addr for addr in self._iter_public_addrs()]
        if not public_addrs:
            raise ValueError("No public addresses", self.instance.networks)
        for netname, address in public_addrs:
            self.test_address(netname, address)

    def delete(self):
        if 'cleanup' in self.params:
            cleanup = self.params['cleanup']
        else:
            cleanup = True
        if cleanup:
            if self.instance:
                try:
                    self.instance.delete()
                finally:
                    if self.volume:
                        self.volume.delete()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    realfile = os.path.realpath(__file__)
    realdir = os.path.dirname(realfile)
    pardir = os.path.realpath(os.path.join(realdir, os.pardir))
    config_file_name = os.path.join(pardir, 'config.ini')
    logger = logging.getLogger("neutronclient.client").setLevel(logging.INFO)
    logger = logging.getLogger("keystoneclient").setLevel(logging.INFO)
    config_file = ConfigParser.SafeConfigParser()
    if not config_file.read(config_file_name):
        raise ValueError("Cannot read config file '%s'" % config_file_name)
    config = dict()
    config.update(config_file.items('DEFAULT'))
    canary = Canary(config)
    try:
        canary.test_public_addrs()
    finally:
        canary.delete()
