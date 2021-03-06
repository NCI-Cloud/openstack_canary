import re
# from openstackclient.common import clientmanager
from keystoneclient import client as keystone_client
from novaclient import client as nova_client
import novaclient.exceptions as nova_exceptions
from cinderclient import client as cinder_client
import cinderclient.exceptions as cinder_exceptions
from glanceclient import client as glance_client
import glanceclient.exc as glance_exceptions
from neutronclient.v2_0 import client as neutron_client
from neutronclient.common.exceptions import Conflict, IpAddressInUseClient
import time
import logging
from pprint import pprint

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
NOVA_API_VERSIONS = ("2", "1.1")
CINDER_API_VERSIONS = ("2", "1")
GLANCE_API_VERSIONS = ("2")


class Session(object):

    def __init__(self, params):
        self.params = params
        self.logger = logging.getLogger(__package__)
        self.nova = None
        self.keystone = None
        self.glance = None
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
        if not self.keystone.authenticate():
            raise ValueError("Keystone authenticate returned false")
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

    def _init_glance(self):
        if self.glance:
            return # Already initialised
        # The Glance client (unlike other clients) needs to be told its service endpoint.
        # So look this up in the Keystone catalog.
        keystone = self.get_keystone()
        if not keystone.has_service_catalog():
            raise ValueError("Keystone unable to provide service catalog")
        url = keystone.service_catalog.url_for(service_type = 'image', endpoint_type = 'public')
        for version in GLANCE_API_VERSIONS:
            try:
                self.glance = glance_client.Client(
                    version,
                    endpoint = url,
                    token = self.token
                )
            except glance_exceptions.ClientException as exc:
                self.logger.debug(
                    "Failed to instantiate Glance client" +
                    " for API version '%s': %s",
                    version,
                    exc
                )
        if self.glance is None:
            raise Exception("No supported Glance API version found")

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

    def get_keystone(self):
        self._init_keystone()
        return self.keystone

    def get_nova(self):
        self._init_nova()
        return self.nova

    def get_glance(self):
        self._init_glance()
        return self.glance

    def get_cinder(self):
        self._init_cinder()
        return self.cinder

    def get_neutron(self):
        self._init_neutron()
        return self.neutron

    def is_available_floating_ip(self, floatip, tenant_id=None):
        return (
            # Belongs to our tenant
            (
               tenant_id is None or
               floatip['tenant_id'] == tenant_id
            ) and
            # Not already connected somewhere
            floatip['port_id'] is None
        )

    def find_available_floating_ip(self, tenant_id=None):
        floatips = self.get_neutron().list_floatingips(
            retrieve_all=False,
            tenant_id=tenant_id
            # FIXME: Returns no results
            # , port_id=None
        )
        for floatip_chunk in floatips:
            for floatip in floatip_chunk['floatingips']:
                if self.is_available_floating_ip(
                    floatip,
                    tenant_id
                ):
                    return floatip
        raise ValueError("No floating IPs available")

    def attach_floating_ip_to_port(self, floatip, port):
        self.get_neutron().update_floatingip(
            floatip['id'],
            dict({
                'floatingip': dict({
                    'port_id': port['id']
                })
            })
        )

    def wait_instance_state(self, instance_id, state):
        attempts = 0
        inst = self.get_nova().servers.get(instance_id)
        state = state.lower()
        while (
            attempts < int(self.params['poll_max'])
            and inst.status.lower() != state
            and inst.status.lower() != 'error'
        ):
            self.logger.debug(
                "Instance '%s' has status '%s', waiting %ds",
                instance_id,
                inst.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))
            inst = self.get_nova().servers.get(instance_id)
        if inst.status.lower() == 'error':
            raise nova_exceptions.InstanceInErrorState()
        if inst.status.lower() != state:
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

    def wait_instance_creation(self, instance_id):
        return self.wait_instance_state(instance_id, 'ACTIVE')

    def create_instance(self, flavour_id, bdm, nics, params):
        instance = self.get_nova().servers.create(
            name=self.params['instance_name'],
            image=self.params['image_id'],
            flavor=flavour_id,
            availability_zone=params['availability_zone'],
            block_device_mapping=bdm,
            nics=nics,
            userdata=params['user_data'],
            key_name=params['key_name'],
            security_groups=params['security_group_names'].split()
        )
        self.wait_instance_creation(instance.id)
        return instance.id

    def _wait_instance_deleted(self, instance_id):
        attempts = 0
        while attempts < int(self.params['poll_max']):
            try:
                inst = self.get_nova().servers.get(instance_id)
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

    def delete_instance(self, instance_id):
        self.get_nova().servers.get(instance_id).delete()
        self._wait_instance_deleted(instance_id)

    def get_server_volumes(self, instance_id):
        return self.get_nova().volumes.get_server_volumes(instance_id)

    def wait_volume_state(self, volume_id, state):
        attempts = 0
        vol = self.get_cinder().volumes.get(volume_id)
        state = state.lower()
        while (
            attempts < int(self.params['poll_max'])
            and vol.status.lower() != state
            and vol.status.lower() != 'error'
        ):
            self.logger.debug(
                "Volume '%s' has status '%s', waiting %ds",
                volume_id,
                vol.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))
            vol = self.get_cinder().volumes.get(volume_id)
        if vol.status.lower() != state:
            raise cinder_exceptions.ClientException(
                "Volume '%s' unexpectedly has status '%s'" %
                (volume_id, vol.status)
            )
        self.logger.info(
            "Volume '%s' has status '%s'",
            volume_id, state
        )

    def wait_volume_creation(self, volume_id):
        return self.wait_volume_state(volume_id, 'available')

    def create_volume(self, params):
        volume = self.get_cinder().volumes.create(
            availability_zone=params['availability_zone'],
            display_name=params['volume_name'],
            size=int(params['volume_size'])
        )
        self.wait_volume_creation(volume.id)
        return volume.id

    def wait_volume_deleted(self, volume_id):
        attempts = 0
        while attempts < int(self.params['poll_max']):
            try:
                vol = self.get_cinder().volumes.get(volume_id)
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

    def wait_image_state(self, image_id, state):
        attempts = 0
        img = self.get_glance().images.get(image_id)
        state = state.lower()
        while (
            attempts < int(self.params['poll_max'])
            and img.status.lower() != state
            and img.status.lower() != 'error'
        ):
            self.logger.debug(
                "Image '%s' has status '%s', waiting %ds",
                image_id,
                img.status,
                int(self.params['poll_secs'])
            )
            attempts += 1
            time.sleep(int(self.params['poll_secs']))
            img = self.get_glance().images.get(image_id)
        if img.status.lower() != state:
            raise glance_exceptions.ClientException(
                "Image '%s' unexpectedly has status '%s'" %
                (image_id, img.status)
            )
        self.logger.info(
            "Image '%s' has status '%s'",
            image_id, state
        )

    def delete_volume(self, volume_id):
        self.get_cinder().volumes.get(volume_id).delete()
        self.wait_volume_deleted(volume_id)

    def attach_any_floating_ip_to_port(self, port):
        attempt_number = 0
        while attempt_number < self.params['poll_max']:
            # Attempt to find a free floating IP
            floatip = self.find_available_floating_ip(
                self.params['tenant_id']
            )
            # NOTE: Window of vulnerability here.
            # At this point, something else can begin using the float.
            try:
                self.attach_floating_ip_to_port(floatip, port)
                self.logger.debug(
                    'Attached float\n%s\nto port\n%s',
                    floatip,
                    port
                )
                self.logger.debug(
                    'Waiting %ss for float to become usable',
                    int(self.params['poll_secs'])
                )
                time.sleep(int(self.params['poll_secs']))
                return floatip
            except (Conflict, IpAddressInUseClient):
                # FIXME: What are the exception types possible when
                # the floating IP address is no longer available,
                # either nonexistent or already used?
                attempt_number += 1
        raise ValueError(
            "Gave up trying to attach a floating IP after " +
            (attempt_number + 1) + " attempts"
        )

    def iter_addrs(self, instance_id):
        for netname, addresslist in self.get_nova().servers.get(
            instance_id
        ).networks.iteritems():
            for address in addresslist:
                yield (netname, address)

    def _is_private(self, address):
        return is_rfc1918(address)

    def _is_public(self, address):
        return not self._is_private(address)

    def iter_private_addrs(self, instance_id):
        for netname, address in self.iter_addrs(instance_id):
            if self._is_private(address):
                yield (netname, address)

    def iter_public_addrs(self, instance_id):
        for netname, address in self.iter_addrs(instance_id):
            if self._is_public(address):
                yield (netname, address)

    def find_image_name_regex(self, regex):
        for image in self.get_glance().images.list():
            # pprint(image)
            if image.name is not None and re.search(r'(?i)' + regex, image.name):
                return image
        raise ValueError("No matching Glance image found")
