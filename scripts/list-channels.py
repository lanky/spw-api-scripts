#!/usr/bin/env python
# -*- coding: utf-8 -*-
# listChannels.py
# pretty print channel labels etc
"""
list-channels.py
pretty-prints a tree of channels in your RHN Satellite.
"""

__author__ = "Stuart Sears <sjs@redhat.com>"

# std library imports
import sys
from optparse import OptionParser, OptionGroup
from operator import itemgetter
import re

# custom module imports
import rhnapi
from rhnapi import channel



#global vars for defaults
RHNHOST='localhost'
RHNCONFIG='~/.rhninfo'
# put these in your configfile, dammit.
RHNUSER=None
RHNPASS=None

def parse_cmdline(argv):
    """
    Deal with commandline arguments
    """
    preamble = "Print a tree of base and child channels to stdout."
    usagestr = "%prog [RHNOPTS] [-cr] [-x REGEX]"
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
    changrp = OptionGroup(parser, "Software Channel Options")
    changrp.add_option("-c","--custom", action = "store_true", default=False, help="only display custom channels, not Red Hat ones.")
    changrp.add_option("-r","--redhat", action = "store_true", default=False, help="only display custom channels, not Red Hat ones.")
    changrp.add_option("-x","--regex", default=None, help="show channels matching the given regular expression. Only matched against base channels." )
    changrp.add_option("-n", "--numbers", default = False, action = "store_true",
        help = "Show number of subscribed systems alongside the labels.")
    parser.add_option_group(changrp)

    return parser.parse_args()
        
# --------------------------------------------------------------------------------- #

def prettify(rhn, chanlist, verbose=False, regex = None, numbers=False):
    """
    pretty-print channels and their children
    requires that the list has been processed using addChildren above
    """
    if float(rhn.sat_version[0:3]) < 5.4:
        # earlier versions of satellite (pre-5.4) don't have the listChildChannels call
        # so we have to do this the hard way
        allchannels = [ channel.detailsByLabel(RHN, x['label']) for x in channel.listAllChannels(RHN) ]
    for chan in chanlist:
        if numbers:
            print "%s (%d)" %(chan, len(channel.listSubscribedSystems(rhn, chan)))
        else:
            print "%s" % chan
        if float(rhn.sat_version[0:3]) < 5.4:
            childchannels = [ x['label'] for x in allchannels if x['parent_channel_label'] == chan ]
        else:
            childchannels =  channel.listChildChannels(rhn, chan)
        has_children = len(childchannels) > 0
        if has_children:            
            for child in childchannels:
                if numbers:
                    print "  |- %s (%d)" % (child, len(channel.listSubscribedSystems(rhn, child)))
                else:
                    print "  |- %s" % child

        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv)
    try:
        # connect to the satellite
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)
        if opts.debug:
            RHN.enableDebug()
        # check for customizations
        if opts.redhat:
            # using the new regex matching in listBaseChannels
            basechannels = channel.listBaseChannels(RHN, '^rhel')
        elif opts.custom:
            basechannels = channel.listBaseChannels(RHN, '^(?!rhel)')
        elif opts.regex is not None:
            basechannels = channel.listBaseChannels(RHN, str(opts.regex))
        else:
            basechannels = channel.listBaseChannels(RHN)
        # prettify(plist, opts.verbose, opts.regex)
        print "channel label (number of subscribed systems)"
        if opts.debug:
            print '\n'.join(basechannels)
        prettify(RHN, basechannels, numbers = opts.numbers)
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)

    


