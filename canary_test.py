#!/usr/bin/python

import os
import logging
import ConfigParser
from openstack_canary.canary import Canary

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    realfile = os.path.realpath(__file__)
    realdir = os.path.dirname(realfile)
    config_file_name = os.path.join(realdir, 'config.ini')
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
