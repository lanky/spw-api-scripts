#!/usr/bin/env python
# -*- coding: utf-8 -*-
# apitemplate.py
"""
delete-configchannel.py
Irrevocably deletes a configuration channel from your satellite.
Back them up first with export-configchannels.py for safety.
"""
# standard library imports
import sys
from optparse import OptionParser, OptionGroup

# custom module imports
# base RHN modules and classes:
import rhnapi
# configuration channel methods:
from rhnapi import configchannel

# global vars for defaults
# At least RHNHOST should  be specified
# if you don't want to use defaults, you should 
# leave these here, but set to None
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
    preamble = "Delete the specified configuration channel(s) from your satellite. Use with care. You might want to back them up first. See 'configchannel2json.py' for one way to do this."
    usagestr = "%prog [OPTIONS] CHANNEL_LABEL..."
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

    # script-specific options
    opts, args = parser.parse_args(argv)

    # do sanity-chacking stuff here
    if len(args) < 1:
        print "You must provide at least one configuration channel label"
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
        for chan in args:
            if configchannel.deleteConfigChannel(RHN, args[0]):
                print "Configuration channel %s deleted" % chan
            else:
                print "failed to delete channel %s" % chan
            

        # do stuff
    except KeyboardInterrupt:
        print "Operation Cancelled\n"
        sys.exit(1)



    

