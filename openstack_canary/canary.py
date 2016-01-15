'''
A Canary OpenStack instance, used to test basic OpenStack functionality.
'''

from openstack_canary.session import Session
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

    def test_ssh_cmd_output(self, ssh, command, pattern):
        regex = re.compile(pattern)
        stdin, stdout, stderr = ssh.exec_command(command)
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

    def test_ssh_script_output(self, ssh, script, args, pattern):
        regex = re.compile(pattern)
        remote_script = '/tmp/canary'
        sftp = ssh.open_sftp()

        def on_progress(so_far, remaining):
            if remaining:
                return  # Not finished yet
            sftp.chmod(remote_script, 755)
            sftp.close()
            # FIXME: Shellcode injection
            stdin, stdout, stderr = ssh.exec_command(
                remote_script + ' ' + ' '.join(args)
            )
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
                raise ValueError("Expected output not found in test script")
        sftp.put(script, remote_script, callback=on_progress, confirm=True)

    tests = dict({
        'echo': dict({
            'match': r'^CANARY_PAYLOAD$'
        }),
        'ping': dict({
            'match': r'[0-9]+ bytes from '
        }),
        'dns': dict({
            'match': r' has (.* )?address'
        }),
        'volume': dict({
            'match': r'^SOME_DATA$'
        })
    })

    def test_ssh(self, ssh, test_name, args):
        self.test_ssh_script_output(
            ssh,
            'test_' + test_name + '.sh',
            args,
            self.tests[test_name]['match']
        )
        self.logger.info(
            "SSH " + test_name + " test successful"
        )

    def test_ssh_echo(self, ssh):
        self.test_ssh(
            ssh,
            'echo',
            ('CANARY_PAYLOAD')
        )

    def test_ssh_ping(self, ssh, host):
        self.test_ssh(
            ssh,
            'ping',
            (host),
        )

    def test_ssh_dns(self, ssh, host):
        self.test_ssh(
            ssh,
            'dns',
            (host)
        )

    def test_ssh_volume(self, ssh, dev):
        self.test_ssh(
            ssh,
            'volume',
            (dev, 'SOME_DATA')
        )

    def ssh(self, address):
        try:
            ssh = SSHClient()
            # ssh.load_system_host_keys()
            """
            VM instances' IP addresses are indeterminate,
            so there is no good way to defend against
            a Man In The Middle attack.
            """
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(address, username=self.params['ssh_username'])
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
        ssh = self.ssh(address)
        self.test_ssh_echo(ssh)
        if 'ssh_ping_target' in self.params and self.params['ssh_ping_target']:
            self.test_ssh_ping(ssh, self.params['ssh_ping_target'])
        if (
            'ssh_resolve_target' in self.params and
            self.params['ssh_resolve_target']
        ):
            self.test_ssh_dns(
                ssh,
                self.params['ssh_resolve_target']
            )
        if self.volume_id:
            self.test_ssh_volume(ssh, self.params['volume_device'])
        ssh.close()

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
