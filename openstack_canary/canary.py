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
RFC1918_PATTERNS = (
    r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
    r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
    r'^192\.168\.\d{1,3}$',
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}$'
)
RFC1918_RES = [re.compile(patt) for patt in RFC1918_PATTERNS]


def is_rfc1918(address):
    for private_re in RFC1918_RES:
        if private_re.match(address):
            return True
    return False


# FIXME: Obtain these from client libraries or Keystone catalog
NOVA_API_VERSIONS = ("3", "2", "1.1")
CINDER_API_VERSIONS = ("2", "1")


class Session(object):

    def __init__(self, params):
        self.params = params
        self.logger = logging.getLogger('openstack_canary.canary.Session')
        self.nova = None
        self.keystone = None
        self.cinder = None
        self.neutron = None
        self.token = None

    def _init_keystone(self):
        if self.keystone:
            return  # Already initialised
        self.keystone = keystone_client.Client(
            username=self.params['username'],
            password=self.params['password'],
            project_name=self.params['tenant_name'],
            auth_url=self.params['auth_url']
        )
        self.keystone.authenticate()
        self.token = self.keystone.auth_ref['token']['id']
        # self.logger.debug("Got token: '%s'", self.token)

    def _init_nova(self):
        if self.nova:
            return  # Already initialised
        for version in NOVA_API_VERSIONS:
            try:
                self.nova = nova_client.Client(
                    version,
                    self.params['username'],
                    self.params['password'],
                    self.params['tenant_name'],
                    self.params['auth_url']
                )
            except nova_exceptions.ClientException as exc:
                self.logger.debug(
                    "Failed to instantiate Nova client" +
                    " for API version '%s': %s",
                    version,
                    exc
                )
        if self.nova is None:
            raise nova_exceptions.UnsupportedVersion()

    def _init_cinder(self):
        if self.cinder:
            return  # Already initialised
        for version in CINDER_API_VERSIONS:
            try:
                self.cinder = cinder_client.Client(
                    version,
                    self.params['username'],
                    self.params['password'],
                    self.params['tenant_name'],
                    self.params['auth_url']
                )
            except cinder_exceptions.ClientException as exc:
                self.logger.debug(
                    "Failed to instantiate Cinder client" +
                    " for API version '%s': %s",
                    version,
                    exc
                )
        if self.cinder is None:
            raise cinder_exceptions.UnsupportedVersion()

    def _init_neutron(self):
        if self.neutron:
            return  # Already initialised
        self.neutron = neutron_client.Client(
            username=self.params['username'],
            password=self.params['password'],
            tenant_name=self.params['tenant_name'],
            auth_url=self.params['auth_url']
        )

    def get_nova(self):
        self._init_nova()
        return self.nova

    def get_cinder(self):
        self._init_cinder()
        return self.cinder

    def get_neutron(self):
        self._init_neutron()
        return self.neutron


class Canary(object):
    '''
    A canary OpenStack instance.
    '''

    def __init__(self, params):
        self.params = params
        self.session = Session(self.params)
        self.logger = logging.getLogger('openstack_canary.canary.Canary')
        self.volume_id = None
        self.flavor_id = None
        self.instance_id = None
        self.floating_ip = None

        if (
            ('flavour_id' in self.params and self.params['flavour_id']) or
            ('flavor_id' in self.params and self.params['flavor_id'])
        ):
            self.flavor_id = (
                self.params['flavour_id'] or self.params['flavor_id']
            )
        else:
            flavor = self.session.get_nova().flavors.find(
                name=self.params['flavour_name']
            )
            self.flavor_id = flavor.id
        if 'volume_id' in self.params and self.params['volume_id']:
            self.volume_id = self.params['volume_id']
            self.own_volume = False
        elif (
            'volume_size' in self.params and
            self.params['volume_size'] and
            int(self.params['volume_size']) > 0
        ):
            self.volume_id = self.create_volume()
            self.own_volume = True
            # NOTE: The path below gets ignored, as the guest kernel
            # numbers block devices itself.
            bdm = dict({self.params['volume_device']: self.volume_id})
        else:
            bdm = None
        if 'network_id' in self.params and self.params['network_id']:
            nics = [dict({'net-id': self.params['network_id']})]
        else:
            nics = None
        self.instance_id = self.create_instance(bdm, nics)
        self.logger.info(
            "Instance '%s': waiting %ds for instance boot",
            self.instance_id,
            int(self.params['boot_wait'])
        )
        time.sleep(int(self.params['boot_wait']))

    def instance(self):
        return self.session.get_nova().servers.get(self.instance_id)

    def volume(self):
        return self.session.get_cinder().volumes.get(self.volume_id)

    def create_instance(self, bdm, nics):
        instance = self.session.get_nova().servers.create(
            name=self.params['instance_name'],
            image=self.params['image_id'],
            flavor=self.flavor_id,
            availability_zone=self.params['availability_zone'],
            block_device_mapping=bdm,
            nics=nics,
            userdata=self.params['user_data'],
            key_name=self.params['key_name'],
            security_groups=self.params['security_group_names'].split()
        )
        self._wait_instance_creation(instance.id)
        return instance.id

    def _wait_instance_creation(self, instance_id):
        attempts = 0
        inst = self.session.get_nova().servers.get(instance_id)
        while (
            attempts < int(self.params['poll_max']) and
            inst.status == 'BUILD'
        ):
            self.logger.debug(
                "Instance '%s' has status '%s', waiting %ds",
                instance_id,
                inst.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))
            inst = self.session.get_nova().servers.get(instance_id)
        if inst.status == 'ERROR':
            self.logger.error(inst.diagnostics())
            raise nova_exceptions.InstanceInErrorState()
        if inst.status != 'ACTIVE':
            self.logger.error(inst.diagnostics())
            raise nova_exceptions.ClientException(
                "Instance '%s' unexpectedly has status '%s'" %
                (instance_id, inst.status)
            )
        self.logger.info(
            "Instance '%s' has status '%s'",
            instance_id,
            inst.status
        )

    def delete_instance(self):
        if self.instance_id:
            self.instance().delete()
            self._wait_instance_deleted(self.instance_id)
            self.instance_id = None

    def _wait_instance_deleted(self, instance_id):
        attempts = 0
        while attempts < int(self.params['poll_max']):
            try:
                inst = self.session.get_nova().servers.get(instance_id)
            except nova_exceptions.NotFound:
                return  # Gone now
            self.logger.debug(
                "Instance '%s' has status '%s', waiting %ds",
                instance_id,
                inst.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))

    def get_attached_volumes(self):
        return self.session.get_nova().volumes.get_server_volumes(self.instance_id)

    def create_volume(self):
        volume = self.session.get_cinder().volumes.create(
            availability_zone=self.params['availability_zone'],
            display_name=self.params['volume_name'],
            size=int(self.params['volume_size'])
        )
        self._wait_volume_creation(volume.id)
        return volume.id

    def _wait_volume_creation(self, volume_id):
        attempts = 0
        vol = self.session.get_cinder().volumes.get(volume_id)
        while (
            attempts < int(self.params['poll_max']) and
            vol.status == 'creating'
        ):
            self.logger.debug(
                "Volume '%s' has status '%s', waiting %ds",
                volume_id,
                vol.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))
            vol = self.session.get_cinder().volumes.get(volume_id)
        if vol.status != 'available':
            raise cinder_exceptions.ClientException(
                "Volume '%s' unexpectedly has status '%s'" %
                (volume_id, vol.status)
            )
        self.logger.info(
            "Volume '%s' created",
            volume_id
        )

    def delete_volume(self):
        if self.volume_id:
            if self.own_volume:
                self.volume().delete()
                self._wait_volume_deleted(self.volume_id)
            self.volume_id = None

    def _wait_volume_deleted(self, volume_id):
        attempts = 0
        while attempts < int(self.params['poll_max']):
            try:
                vol = self.session.get_cinder().volumes.get(volume_id)
            except cinder_exceptions.NotFound:
                return  # Gone now
            self.logger.debug(
                "Volume '%s' has status '%s', waiting %ds",
                volume_id,
                vol.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))

    def _is_private(self, address):
        return is_rfc1918(address)

    def _is_public(self, address):
        return not self._is_private(address)

    def _iter_addrs(self):
        for netname, addresslist in self.instance().networks.iteritems():
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
            ports = self.session.get_neutron().list_ports(
                retrieve_all=False,
                device_id=self.instance_id,
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
        floatips = self.session.get_neutron().list_floatingips(
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
        self.session.get_neutron().update_floatingip(
            floatip['id'],
            dict({
                'floatingip': dict({
                    'port_id': port['id']
                })
            })
        )

    def attach_any_floating_ip_to_port(self, port):
        attempt_number = 0
        while attempt_number < self.params['poll_max']:
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
                    int(self.params['poll_secs'])
                )
                time.sleep(int(self.params['poll_secs']))
                return
            except (Conflict, IpAddressInUseClient):
                # FIXME: What are the exception types possible when
                # the floating IP address is no longer available,
                # either nonexistent or already used?
                attempt_number += 1
        raise ValueError(
            "Gave up trying to attach a floating IP after " +
            (attempt_number + 1) + " attempts"
        )

    def attach_any_floating_ip_to_any_private_port(self):
        for port in self._iter_ports_of_private_ips():
            self.attach_any_floating_ip_to_port(port)
            return

    def make_internet_accessible(self):
        public_addrs = [addr for addr in self._iter_public_addrs()]
        if not public_addrs:
            self.logger.debug(
                "Instance has no public addresses automatically;" +
                " attempting to attach a floating IP"
            )
            self.attach_any_floating_ip_to_any_private_port()

    def test_ssh_cmd_output(self, client, command, pattern):
        regex = re.compile(pattern)
        stdin, stdout, stderr = client.exec_command(command)
        found_canary = False
        stdin.close()
        stdout_lines = [line for line in stdout]
        for line in stdout_lines:
            line = line.rstrip()
            if regex.match(line):
                found_canary = True
        if not found_canary:
            stderr_lines = [line for line in stderr]
            self.logger.debug('STDERR:\n' + ''.join(stderr_lines))
            self.logger.debug('STDOUT:\n' + ''.join(stdout_lines))
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

    def test_ssh_volume(self, client):
        if not self.volume_id:
            return  # Requires a volume
        dev = self.params['volume_device']
        self.test_ssh_cmd_output(
            client,
            'sudo mkfs.ext4 ' + dev +
            ' && sudo mount ' + dev + ' /mnt' +
            ' && sudo sh -c "echo SOME_DATA > /mnt/testfile"' +
            ' && sudo cat /mnt/testfile' +
            ' && sudo rm /mnt/testfile' +
            ' && sudo umount /mnt',
            r'^SOME_DATA$'
        )
        self.logger.info(
            "SSH volume test successful"
        )

    def test_address(self, netname, address):
        self.logger.info(
            "Testing address '%s' on network '%s'",
            address,
            netname
        )
        try:
            client = SSHClient()
            # client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(address, username=self.params['ssh_username'])
        except:
            self.logger.debug(self.instance().get_console_output(10))
            raise
        self.test_ssh_echo(client)
        if 'ssh_ping_target' in self.params and self.params['ssh_ping_target']:
            self.test_ssh_ping_host(client, self.params['ssh_ping_target'])
        if (
            'ssh_resolve_target' in self.params and
            self.params['ssh_resolve_target']
        ):
            self.test_ssh_resolve_host(
                client,
                self.params['ssh_resolve_target']
            )
        self.test_ssh_volume(client)

    def test_public_addrs(self):
        self.make_internet_accessible()
        public_addrs = [addr for addr in self._iter_public_addrs()]
        if not public_addrs:
            raise ValueError("No public addresses", self.instance().networks)
        for netname, address in public_addrs:
            self.test_address(netname, address)

    def delete(self):
        if 'cleanup' in self.params:
            cleanup = self.params['cleanup']
        else:
            cleanup = True
        if cleanup:
            try:
                self.delete_instance()
            finally:
                self.delete_volume()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    realfile = os.path.realpath(__file__)
    realdir = os.path.dirname(realfile)
    pardir = os.path.realpath(os.path.join(realdir, os.pardir))
    config_file_name = os.path.join(pardir, 'config.ini')
    logging.getLogger("neutronclient.client").setLevel(logging.INFO)
    logging.getLogger("keystoneclient").setLevel(logging.INFO)
    logging.getLogger("paramiko.transport").setLevel(logging.INFO)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
    logging.getLogger(__package__).setLevel(logging.DEBUG)
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
