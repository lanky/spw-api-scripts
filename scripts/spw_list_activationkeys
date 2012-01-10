#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from optparse import OptionParser, OptionGroup
import re

import rhnapi
from rhnapi import channel
from rhnapi import systemgroup
from rhnapi import activationkey

__doc__ = """
print a pretty table of the activation keys on your satellite
"""

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

ent_maps = { 'provisioning_entitled'   : 'provisioning',
             'monitoring_entitled'     : 'monitoring',
             'virtualization_host'     : 'virt',
             'virtualization_platform' : 'virt-platform',
}

react_re = re.compile(r'^(Kickstart )?(Reactivation|re-activation) Key.*$', re.I)
# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "List activationkeys on your RHN Satellite server."
    usagestr = "%prog [RHNOPTS]"
    # initialise our parser and set some default options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc")
    parser.add_option('-v', '--verbose', action = 'store_true', default = False,
            help = "increase verbosity")

    # RHN Satellite options group
    rhngrp = OptionGroup(parser, "RHN Satellite Options", "Defaults can be set in your RHN API config file (%s)" % RHNCONFIG )
    rhngrp.add_option("--server",help="RHN satellite server hostname [%default]", default=RHNHOST)
    rhngrp.add_option("--login", help="RHN login (username)" , default=RHNUSER)
    rhngrp.add_option("--pass", dest = "password", help="RHN password. This is better off in a config file.", default=RHNPASS)
    rhngrp.add_option("--config", dest = "config", help="Local RHN configuration file [ %default ]", default=RHNCONFIG)
    rhngrp.add_option("--cache", action = "store_true", default = False,
        help = "save usernames and password in config file, if missing")
    parser.add_option_group(rhngrp)
    
    parser.add_option("-r", "--reactivation-keys", action = "store_true", default = False, help = "Include Reactivation keys in list [%default]")

    # script-specific options
    opts, args = parser.parse_args()
    # check the args for errors etc...

    # finally...
    return opts, args


if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv)
    # initialiase an RHN Session
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)
        if opts.debug:
            RHN.enableDebug()
        print "%-40s   Description" % "Key"
        print "----------------------------------------   ----------------------"
        for actkey in rhnapi.activationkey.listActivationKeys(RHN):
            if react_re.search(actkey['description']) and not opts.reactivation_keys:
                continue
            else:
                print "%(key)-40s | %(description)s" % actkey
        # DO STUFF
    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)


    
    
    
