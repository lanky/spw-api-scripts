#!/usr/bin/env python
# -*- coding: utf-8 -*-
# apitemplate.py
"""
delete-kickstart.py
Irrevocably deletes a kickstart profile from your satellite
back them up first using export-kickstarts.py
"""
import rhnapi
#from rhapi import system
from rhnapi import kickstart

import sys
from optparse import OptionParser, OptionGroup

# global vars for defaults
# At least RHNHOST *must* be specified.
RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

def parse_cmdline(argv):
    """
    process the commandline :)
    give this sys.argv[1:] as an argument to avoid any issues with the script name
    being considered an 'argument' and processed
    """
    preamble = "Delete the provided kickstart profile from your satellite. Use with care."
    usagestr = "%prog [OPTIONS] KICKSTART_LABELS"
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
        help="Cache provided credentials in config file" )
    parser.add_option_group(rhngrp)

    ksgrp = OptionGroup(parser, "kickstart options")
    ksgrp.add_option("--list", action = "store_true", default = False,
        help = "simply list existing kickstart profiles and exit")
    parser.add_option_group(ksgrp)

    # script-specific options
    opts, args = parser.parse_args(argv)

    # so sanity-chacking stuff here
    if len(args) == 0 and not opts.list:
        print "ERROR"
        print "You must provide a kickstart label or the --list option"
        parser.print_help()
        sys.exit(1)

    # finally return the cleaned options and args
    return opts, args



if __name__ == '__main__':
    
    # process command-line arguments
    opts, args = parse_cmdline(sys.argv[1:])
    # initiate a connection to 
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()
        # list of kickstart profiles
        all_kickstarts = kickstart.listKickstarts(RHN)
        # just their labels for 'does this exist?' and '--list' options
        ks_labels = [ x.get('label') for x in all_kickstarts ]

        if opts.list:
            print "Existing Kickstart labels"
            print "========================="
            print '\n'.join(ks_labels)
            sys.exit(0)

        for kslabel in args:
            if kslabel not in ks_labels:
                print "no such kickstart profile: %s" % kslabel

            if kickstart.deleteProfile(RHN, args[0]):
                print "kickstart profile %s deleted" % args[0]
            else:
                print "failed to delete profile %s" % args[0]
            

        # do stuff
    except KeyboardInterrupt:
        print "Operation Cancelled\n"
        sys.exit(1)



    

