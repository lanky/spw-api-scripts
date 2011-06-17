#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to clone a channel for when the web
# interface is inaccessible
"""
delete-channel.py

RHN XMLRPC API script to delete the chosen channel.

requires the rhnapi python module
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

import sys
from optparse import OptionParser, OptionGroup

import rhnapi
from rhnapi import channel
from rhnapi import utils

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Delete a channel in your RHN Satellite. "
    usagestr = "%prog [RHNOPTS...] [-ri] -c CHANNEL"
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
    changrp = OptionGroup(parser, "Channel Options")
    changrp.add_option('-c','--channel', dest = 'channel', help = 'channel LABEL you wish to delete', default=None)
    changrp.add_option('-r', '--recursive', help = 'delete channel recursively, removing all children (dangerous)', action = 'store_true', default=False)
    changrp.add_option('-i', '--interactive', action = 'store_true', default = False,
            help = "interactive mode - prompt before deleting")
    parser.add_option_group(changrp)

    opts, args = parser.parse_args()
    # check the args for errors etc...

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv)
    # initialiase an RHN Session
#    print "This is under heavy development and is currenttly non-functional"
#    sys.exit(0)
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()

        existing_channels = [ x['label'] for x in channel.listSoftwareChannels(RHN) ]

        for chan in opts.channel.split(','):
            if chan not in existing_channels:
                print "source channel %s does not exist. Skipping it." % chan
                if opts.interactive:
                    print "The following channels exist on your satellite:"
                    print '\n'.join(existing_channels)
                    chan = utils.prompt_missing('Channel label: ')
                continue

            child_chans = channel.listChildChannels(RHN, chan)
            has_children = len(child_chans) > 0

            # does this have child channels?
            if has_children:
                if opts.recursive:
                    for child in child_chans:
                        if opts.interactive:
                            if not utils.prompt_confirm("Delete channel %s" % child, "Y"):
                                continue
                        if opts.verbose:
                            print "deleting child channel %s" % child
                        if channel.delete(RHN, child):
                           print "deleted child channel %s" % child
                else:
                    print 'channel %s has child channels. please delete them first or use the -r/--recursive option' % chan
                    print 'children:'
                    print '\n'.join( child_chans)
                    sys.exit(2)
            
            if channel.delete(RHN, chan):
                print "deleted channel %s" % chan

    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)


    
    
    
