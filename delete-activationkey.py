#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to delete the chosen activation keys from your satellite.
# be very very careful. ideally back them up using
# actkey2json first
__doc__ = """
Deletes the provided (list of) Activation Key(s) from your satellite
Requires either a username/password or a configuration file (~/.rhninfo)
with this information in it.

WARNING
This script irrevocably removes activation keys from your satellite.
use with care. Preferably backup the keys using export-activation-keys.py first
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

# python standard library imports
import sys
import re
from optparse import OptionParser, OptionGroup

# custom rhnapi modules. Make sure they're on your
# PYTHONPATH (or in the same dir as this script)
import rhnapi
from rhnapi import activationkey


## -------------- Customisation ------------------ ##
# At least RHNHOST *must* be specified (or provided on the commandline)
# if you wish it unset, set it to None here (no quotes)
RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None
react_pattern = re.compile(r'^(Kickstart )?(Reactivation|re-activation) Key.*$', re.I)

## -------------- The script itself  ------------ ##
def parse_cmdline(argv):
    """
    process the commandline :)
    give this sys.argv[1:] as an argument to avoid any issues with the script name
    being considered an 'argument' and processed
    """
    preamble = "Delete the provided activation key(s) [the long hex ids] from your satellite. Use with care."
    usagestr = "%prog [RHNOPTS] ACTIVATIONKEY..."
    # initialise our parser and set some generic options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc")
    parser.add_option("-v", "--verbose", action = "store_true", default = False,
            help = "increase verbosity of output")

    # RHN Satellite options group
    rhngrp = OptionGroup(parser, "RHN Satellite Options", "Defaults can be set in your RHN API config file (%s)" % RHNCONFIG )
    rhngrp.add_option("--server",help="RHN satellite server hostname [%default]", default=RHNHOST)
    rhngrp.add_option("--login", help="RHN login (username)" , default=RHNUSER)
    rhngrp.add_option("--pass", dest = "password", help="RHN password. This is better off in a config file.", default=RHNPASS)
    rhngrp.add_option("--config", dest = "config", help="Local RHN configuration file [ %default ]", default=RHNCONFIG)
    rhngrp.add_option("--cache", action = "store_true", default = False,
        help = "save usernames and password in config file, if missing")
    parser.add_option_group(rhngrp)

    # script-specific options
    keygrp = OptionGroup(parser,"Activation Key Options")
    keygrp.add_option("--list", action = "store_true", default = False, help = "List activation keys and exit [%default]")
    keygrp.add_option("-r", "--include-reactivation", action = "store_true", default = False, help = "Include Reactivation keys in listings [%default]")
    parser.add_option_group(keygrp)

    opts, args = parser.parse_args(argv)

    # finally return the cleaned options and args
    return opts, args
        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    # process command-line arguments
    opts, args = parse_cmdline(sys.argv[1:])
    # initiate a connection to 
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()

        all_keys = activationkey.listActivationKeys(RHN)

        if not opts.include_reactivation:
            if opts.verbose:
                print "Removing reactivation keys from our key list"
            all_keys = [ x for x in all_keys if not react_pattern.match(x['description'])]

        if opts.list:
            print "Activation Keys on your satellite"
            if not opts.include_reactivation:
                print "(Reactivation Keys Excluded)"
            if len(all_keys) == 0:
                print "(No Activation Keys found)"
                sys.exit(0)
            print "%-36s %s" %("Activation Key", "Description")
            print "-----------------------------------  ------------------------------------"
            for actkey in all_keys:
                print "%(key)-36s %(description)s" % actkey
            sys.exit(0)

        for akey in args:
            if activationkey.delete(RHN, akey):
                print "activation key %s deleted" % akey
            else:
                print "failed to delete activation key %s" % akey

    except KeyboardInterrupt:
        print "Operation Cancelled\n"
        sys.exit(1)



    

