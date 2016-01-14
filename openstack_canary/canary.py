#!/usr/bin/python

'''
A Canary OpenStack instance, used to test basic OpenStack functionality.
'''

import os
import ConfigParser
from paramiko.client import SSHClient
from paramiko import AutoAddPolicy
# from openstackclient.common import clientmanager
from keystoneclient import client as keystone_client
from novaclient import client as nova_client
import novaclient.exceptions as nova_exceptions
from cinderclient import client as cinder_client
import cinderclient.exceptions as cinder_exceptions
from neutronclient import client as neutron_client
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
            bdm=dict({'/dev/vdz': self.volume.id})
        else:
            self.volume = None
            bdm=None
        if 'network_id' in params and params['network_id']:
            nics=[ dict({'net-id': params['network_id']}) ]
        else:
            nics=None
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
                "Instance has status '%s', waiting %ds",
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
            "Instance has status '%s', waiting %ds for boot",
            self.instance.status,
            int(params['boot_wait'])
        )
        time.sleep(int(params['boot_wait']))

    def test_ssh_echo(self, client):
        stdin, stdout, stderr = client.exec_command('echo CANARY_PAYLOAD')
        found_canary = False
        for line in stdout:
            line = line.rstrip()
            # self.logger.debug('STDOUT: ' + line)
            if line == "CANARY_PAYLOAD":
                found_canary = True
        if found_canary:
            self.logger.info(
                "SSH echo test successful"
            )
        else:
            for line in stderr:
                line = line.rstrip()
                self.logger.debug('STDERR: ' + line)
            raise ValueError("Expected output not found in test command")

    def test_ssh_address(self, netname, address):
        self.logger.info(
            "Attempting to SSH to '%s' on network '%s'",
            address,
            netname
        )
        try:
            client = SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(address, username=self.params['ssh_username'])
        except:
            self.logger.debug(self.instance.get_console_output())
            raise
        self.test_ssh_echo(client)

    def test_ssh(self):
        for name, addresslist in self.instance.networks.iteritems():
            for address in addresslist:
                self.test_ssh_address(name, address)

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
    config_file = ConfigParser.SafeConfigParser()
    if not config_file.read(config_file_name):
        raise ValueError("Cannot read config file '%s'" % config_file_name)
    config = dict()
    config.update(config_file.items('DEFAULT'))
    canary = Canary(config)
    try:
        canary.test_ssh()
    finally:
        canary.delete()
