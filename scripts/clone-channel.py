#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to clone a channel for when the web
# interface is inaccessible

"""
clone-channel.py

A script to clone a channel in your RHN Satellite, with or without errata.

This requires the presence of the 'rhnapi' module on your PYTHONPATH.
"""

import sys
from optparse import OptionParser, OptionGroup

# custom module imports
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
    preamble = "Clone a channel in your RHN Satellite. "
    usagestr = "%prog [OPTIONS] [-p PARENT] -c SOURCECHANNEL -d DESTCHANNEL"
    # intitialise our parser instance and set some core options
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

    changrp = OptionGroup(parser, "Channel Options")
    changrp.add_option("-c","--source-channel", dest = "source", help = "source channel LABEL", default=None)
    changrp.add_option("-d","--dest-channel", dest = "dest", help = "destination channel LABEL", default=None)
    changrp.add_option("-n","--no-errata", help="do not clone errata [%default]", action="store_true", default=False)
    changrp.add_option("-p","--parent", help="parent for new channel. Your new channel will be a base channel without this.", default=None)
    changrp.add_option("-s","--summary", help="Channel Summary - dest label used if omitted.", default=None)
    changrp.add_option("-i", "--interactive", help = "run in interactive mode [%default]", action = "store_true", default=False)
    parser.add_option_group(changrp)


    opts, args = parser.parse_args()
    if opts.source is None:
        print "no source channel label provided"
        if opts.interactive:
            opts.source = utils.prompt_missing('source channel LABEL: ')
        else:
            parser.print_help()
            sys.exit(1)
    
    if opts.dest is None:
        print "no destination channel label provided"
        if opts.interactive:
            opts.dest = utils.prompt_missing('destination channel LABEL: ')
        else:
            parser.print_help()
            sys.exit(1)

    if opts.summary is None:
        opts.summary = opts.dest

    return opts, args

# --------------------------------------------------------------------------------- #

def label_to_name(label):
    """
    perform some basic substitutions on a string to make it suitable for a channel Name, rather than a label
    Essentially, this removes all the hyphens, uppercases RHEL, RHN, ES, AS, WS, title cases the rest.
    """
    capwords = [ 'rhn', 'rhel', 'as', 'es', 'ws' ]
    # at the moment these are the only arches we have...
    arches = [ 'i386', 'x86_64' ]
    output = []
    for word  in label.split('-'):
        if word in capwords:
            output.append(word.upper())
        elif  word in arches:
            output.append(word)
        else:
            output.append(word.capitalize())
    return ' '.join(output)


if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv)

    # initialiase an RHN Session
    
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()

        channels = [ x['label'] for x in channel.listSoftwareChannels(RHN) ]
        # existing_channels = [ x['label'] for x in  channellist ]
        parents = channel.listBaseChannels(RHN)

        if opts.source not in channels:
            print "source channel %s does not exist. Please try again" % opts.source
            print "The following channels exist on your satellite:"
            print '\n'.join(channels)
            if opts.interactive:
                opts.src = utils.prompt_missing('Source Channel label: ')
            else:
                sys.exit(1)

        if opts.dest in channels:
            print "Destination Channel label %s already exists. Please Choose an alternative" % opts.dest
            if opts.interactive:
                opts.dest = utils.prompt_missing('Destination Channel Label: ')
            else:
                sys.exit(2)

        if opts.parent is not None and opts.parent not in parents:
            print "Parent Channel is not an existing Base Channel. Please choose one of the following:"
            print '\n'.join(parents)
            if opts.interactive:
                opts.parent = utils.prompt_missing('Parent Channel Label: ')


        # okay, we have the information I need, let's try...
        kwargs = {'label' : opts.dest, 'name': label_to_name(opts.dest), 'summary': opts.summary }
        if opts.parent:
            kwargs['parent_label'] = opts.parent
        if opts.verbose:
            print "cloning channel"
        if channel.cloneChannel(RHN, opts.source, opts.no_errata, **kwargs):
            print "Successfully cloned %s as %s" %(opts.source, opts.dest)
    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)


    
    
    
