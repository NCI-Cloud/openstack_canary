'''
A Canary OpenStack instance, used to test basic OpenStack functionality.
'''

from openstack_canary.session import Session
import stat
import time
import re
from paramiko.client import SSHClient
from paramiko import AutoAddPolicy
import logging
MODULE_LOGGER = logging.getLogger('openstack_canary.canary')


class Canary(object):
    '''
    A canary OpenStack instance.
    '''

    def __init__(self, params):
        self.params = params
        self.session = Session(self.params)
        self.logger = logging.getLogger(__package__)
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
            self.volume_id = self.session.create_volume(self.params)
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
        self.instance_id = self.session.create_instance(
            self.flavor_id,
            bdm,
            nics,
            self.params
        )
        self.logger.info(
            "Instance '%s': waiting %ds for instance boot",
            self.instance_id,
            int(self.params['boot_wait'])
        )
        time.sleep(int(self.params['boot_wait']))

    def delete_instance(self):
        if self.instance_id:
            self.session.delete_instance(self.instance_id)
            self.instance_id = None

    def instance(self):
        return self.session.get_nova().servers.get(self.instance_id)

    def volume(self):
        return self.session.get_cinder().volumes.get(self.volume_id)

    def get_attached_volumes(self):
        return self.session.get_server_volumes(self.instance_id)

    def delete_volume(self):
        if self.volume_id:
            if self.own_volume:
                self.session.delete_volume(self.volume_id)
            self.volume_id = None

    def _iter_ports_of_private_ips(self):
        for (netname, address) in self.session.iter_private_addrs(
            self.instance_id
        ):
            ports = self.session.get_neutron().list_ports(
                retrieve_all=False,
                device_id=self.instance_id,
                fixed_ip_address=address
            )
            for port_group in ports:
                for port in port_group['ports']:
                    self.logger.debug('Port of private address: %s', port)
                    yield port

    def attach_any_floating_ip_to_any_private_port(self):
        for port in self._iter_ports_of_private_ips():
            self.floating_ip = self.session.attach_any_floating_ip_to_port(
                port
            )
            return

    def make_internet_accessible(self):
        public_addrs = [addr for addr in self.session.iter_public_addrs(
            self.instance_id
        )]
        if not public_addrs:
            self.logger.debug(
                "Instance has no public addresses automatically;" +
                " attempting to attach a floating IP"
            )
            self.attach_any_floating_ip_to_any_private_port()

    def test_ssh_script_output(self, address, script, args, pattern):
        ssh = self.ssh(address)
        regex = re.compile(pattern)
        remote_script = '/tmp/' + script
        sftp = ssh.open_sftp()
        sftp.put(script, remote_script, confirm=True)
        sftp.chmod(remote_script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        sftp.close()
        ssh.close()
        ssh = self.ssh(address)
        # FIXME: Shellcode injection
        stdin, stdout, stderr = ssh.exec_command(
            remote_script + ' ' + ' '.join(args)
        )
        found_pattern = False
        stdin.close()
        for line in stdout:
            line = line.rstrip()
            if regex.match(line):
                found_pattern = True
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0 or not found_pattern:
            stderr_lines = [line for line in stderr]
            self.logger.debug('STDERR:\n' + ''.join(stderr_lines))
            self.logger.debug('STDOUT:\n' + ''.join(stdout_lines))
            raise ValueError("Test script did not yield expected output and exit status")
        ssh.close()

    tests = dict({
        'echo': dict({
            'match': r'^CANARY_PAYLOAD$'
        }),
        'ping': dict({
            'match': r'[0-9]+ bytes from '
        }),
        'dns': dict({
            'enabled': False,
            'match': r' has (.* )?address'
        }),
        'volume': dict({
            'match': r'^SOME_DATA$'
        })
    })

    def test_ssh(self, address, test_name, args):
        self.test_ssh_script_output(
            address,
            'test_' + test_name + '.sh',
            args,
            self.tests[test_name]['match']
        )
        self.logger.info(
            "SSH " + test_name + " test successful"
        )

    def test_echo(self, address, params):
        return self.test_ssh(
            address,
            'echo',
            [ 'CANARY_PAYLOAD' ]
        )

    def test_ping(self, address, params):
        if 'ssh_ping_target' not in params or not params['ssh_ping_target']:
            return # No ping test configured
        host = params['ssh_ping_target']
        self.test_ssh(
            address,
            'ping',
            [ host ],
        )

    def test_dns(self, address, params):
        if (
            'ssh_resolve_target' not in params or
            not params['ssh_resolve_target']
        ):
            return # Test not configured
        return self.test_ssh(
            address,
            'dns',
            [ host ]
        )

    def test_volume(self, address, params):
        if not params['volume_device']:
            return # Test not configured
        dev = params['volume_device']
        return self.test_ssh(
            address,
            'volume',
            [ dev, 'SOME_DATA' ]
        )

    def ssh(self, address):
        try:
            ssh = SSHClient()
            # ssh.load_system_host_keys()
            """
            VM instances' IP addresses are indeterminate,
            so there is no good way to detect
            a Man In The Middle attack.
            The fact that a different instance now has the same IP address
            could be a MITM attack, or it could be due to deletion
            of the old instance, or it could be due to re-arranging of
            IP addresses among the same set of instances.
            We don't care much about MITM attacks anyway - they would
            merely cause us to test the correct functioning of some
            attacker's computer, instead of our instance, which would
            be bad only if the attacker's computer were less broken
            than our instance, thus hiding problems with our instance.
            This is a less bad problem than SSH connectivity randomly
            failing when IP addresses get re-used.
            So just disable protection against MITM attacks, by:
            1. Auto-adding unknown hosts to the known hosts file and
            2. Not loading any known hosts files.
            """
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(address, username=self.params['ssh_username'], key_filename=self.params['ssh_key_file'])
        except:
            self.logger.debug(self.instance().get_console_output(10))
            raise
        return ssh

    def test_address(self, netname, address):
        self.logger.info(
            "Testing address '%s' on network '%s'",
            address,
            netname
        )
        for test_name, test in self.tests.iteritems():
            if 'enabled' not in test or test['enabled']:
                func = getattr(self, 'test_' + test_name)
                func(address, self.params)

    def test_public_addrs(self):
        self.make_internet_accessible()
        public_addrs = [addr for addr in self.session.iter_public_addrs(
            self.instance_id
        )]
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
