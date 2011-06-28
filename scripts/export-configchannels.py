#!/usr/bin/env python
# -*- coding: utf-8 -*-
# apitemplate.py
"""
export-configchannels.py
Exports the specified configuration channels, including all file content to a JSON-format text file.
"""
# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup
import time

# custom modules. Make sure they're on your PYTHONPATH
# hint:
# sys.path.append('parent directory of rhnapi')

import rhnapi
from rhnapi import configchannel
# utility functions
from rhnapi import utils

#from rhapi import system
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
    preamble = "Exports the chosen configuration channels to files in JSON format"
    usagestr = "%prog [OPTIONS] CONFIGCHANNELS..."
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
    ccgrp = OptionGroup(parser, "Configuration Channel Options")
    ccgrp.add_option("--list", action="store_true", default=False, help="just list config channels and exit")
    ccgrp.add_option("-f","--filename", default=False, help="Output filename (calculated otherwise)")
    parser.add_option_group(ccgrp)

    opts, args = parser.parse_args(argv)

    # so sanity-chacking stuff here

    # finally return the cleaned options and args
    return opts, args
    
def get_confchannel_info(rhn, channel_label, verbose=False):
    """
    processes the specified channels, getting filelists and metadata
    """
    channeldata = configchannel.detailsByLabel(rhn, channel_label)
    filelist = [ x['path'] for x in configchannel.listFiles(RHN, channel_label) ]
    channeldata['files'] = []
    for fentry in configchannel.lookupFileInfo(RHN, channel_label, filelist):
        if verbose:
            print "processing file %s" % fentry['path']
        #fentry['modified'] = str(fentry['modified'])
        #fentry['creation'] = str(fentry['creation'])
        channeldata['files'].append(fentry)
    return channeldata



if __name__ == '__main__':
    
    # process command-line arguments
    opts, args = parse_cmdline(sys.argv[1:])
    # initiate a connection to 
    global existing_config_channels

    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()

        # get a list of all existing channels for listing
        existing_config_channels = configchannel.listGlobals(RHN)
        existing_labels = [ x['label'] for x in existing_config_channels ]

        if opts.list:
            print "Existing Global Configuration Channels:"
            print '\n'.join(existing_labels)
            sys.exit(0)

        # this is where we're going to put our channel data:
        blended_config_channels = []
        if len(args) > 0:
            channel_list = args
            print "using channels %s" % ','.join(channel_list)
        else:
            if opts.verbose:
                print "no channel specified. dumping ALL config channels"
            channel_list = existing_labels

        for chan in channel_list:
            print "processing channel '%s'" % chan
            if chan in existing_labels:
                if opts.verbose:
                    print "looking up data for channel %s" % chan
                chandata = get_confchannel_info(RHN, chan, opts.verbose)
                blended_config_channels.append(chandata)
            else:
                print "channel %s does not appear to exist on this satellite. Skipping." % chan
                continue
    
        if opts.filename:
            outfile = opts.filename
        else:
            outfile = "configchannel_export-%s-%s.json" %(RHN.hostname,time.strftime('%Y%m%d.%H%M'))
        if len(blended_config_channels) > 0:
            if opts.verbose:
                print "saving channel data for selected channels to file %s" % outfile
            # if save_as_json(outfile, blended_config_channels, opts.verbose):
            if utils.dumpJSON(blended_config_channels, outfile, verbose = opts.verbose):
                print "saved data"

        else: print "Nothing to save. This should not happen."


        # do stuff
    except KeyboardInterrupt:
        print "Operation Cancelled\n"
        sys.exit(1)



    

