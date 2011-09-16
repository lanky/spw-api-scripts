#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to clone a channel for when the web
# interface is inaccessible
"""
create-channel.py

An RHN XMLRPC API script to create a new channel in satellite.

requires the rhnapi python module somewhere on your PYTHONPATH
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

import rhnapi
from rhnapi import channel
import sys
from optparse import OptionParser, OptionGroup

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your coonfig file
RHNUSER = None
RHNPASS = None

def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Create a new channel in RHN based on the options given"
    usagestr = "%prog [RHNOPTS] -c CHANNEL [OTHEROPTS]"
    # initialise our parser and set some default options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc")
    parser.add_option("-v", "--verbose", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc")

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
    changrp.add_option("-c","--channel", help = "Channel LABEL", default=None)
    changrp.add_option("-n","--name", help = "Channel NAME (defaults to the label) ", default=None)
    changrp.add_option("-s","--summary", help = "Channel summary (defaults to the label) ", default=None)
    changrp.add_option("-a","--arch", help = "Channel Architecture [%default] ", default="x86_64")
    changrp.add_option("-p", "--parent", help="Parent for new channel. Default is a base channel", default="")
    parser.add_option_group(changrp)


    opts, args = parser.parse_args()

    # process the args and return the valid ones...
    if opts.channel is None:
        print "you must provide a label for your new channel"
        sys.exit(1)
    # handle the purely weird channel architecture labels.
    if not opts.arch.startswith('channel-'):
        opts.arch = "channel-%s" % opts.arch
    
    if opts.name is None:
        opts.name = opts.channel.strip()
    
    if opts.summary is None:
        opts.summary = opts.channel.strip()

    # ignore all extraneous args:
    return opts

if __name__ == '__main__':
    
    opts = parse_cmdline(sys.argv)

    # initialiase an RHN Session
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)
        if opts.debug:
            RHN.enableDebug()

        # get the existing channel list:
        chanlist     = channel.listAllChannels(RHN)
        chanlabels   = [ x['label'] for x in  chanlist ]
        parentlabels = channel.listBaseChannels(RHN)

    # check if the desired label is already used
        if opts.channel in chanlabels:
            print "Channel label %s already exists. Please Choose an alternative" % channel
            sys.exit(3)

    # if a parent channel is specified, does it already exist?
        if opts.parent != '' and opts.parent not in chanlabels:
            print "Parent Channel does not exist. Please choose one of the following:"
            print '\n'.join(parentlabels)

        # okay, we have the information I need, let's try...

        if channel.create(RHN, opts.channel, opts.name.strip(), opts.summary.strip(), opts.arch.strip(), parent=opts.parent.strip()):
            print "channel %s successfully created" % opts.channel
        else:
            print "Failed to create channel. Oops."
            
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)
        print
