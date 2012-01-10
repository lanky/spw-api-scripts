#!/usr/bin/env python
# -*- coding: utf-8 -*-
# json2configchannel.py
# A script to create config channels on an RHN satellite from JSON dumps
# author: Stuart Sears <sjs@redhat.com>
# This script may or may not do unpleasant things to your satellite.
# make backups first.

__doc__ = """
import-configchannels.py
A script to recreate configuration channels on a satellite from a JSON dump.
(JSON dump created by the counterpart export-configchannels.py script.)
It will:
* create a configchannel
* create and populate files, directories and symlinks, based on the JSON content.
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup

# custom modules. Make sure they're on your PYTHONPATH
# hint:
# sys.path.append('parent directory of rhnapi')

import rhnapi
from rhnapi import configchannel
from rhnapi import utils

# global vars for defaults
# At least RHNHOST *must* be specified.
RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None
        
# --------------------------------------------------------------------------------- #

def parse_cmdline(argv):
    """
    process the commandline :)
    give this sys.argv[1:] as an argument to avoid any issues with the script name
    being considered an 'argument' and processed
    """
    preamble = "import configuation channels from the provided JSON-format text file. File modification and creation times will be lost on import."
    usagestr = "%prog [OPTIONS] JSONFILE"
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
    ccgrp.add_option("-c","--channel",
        help="Channel to create/import from JSON file. Default is ALL channels")
    ccgrp.add_option("--list", action="store_true", default=False,
        help="just list config channel labels in the JSON file and exit")
    ccgrp.add_option("-u","--update", action="store_true", default = False,
        help="Update existing channels, rather than skipping them. Use with caution.")
    ccgrp.add_option("-r","--replace", action="store_true", default = False,
        help="Replace (delete and recreate) existing channels, rather than skipping them. Use with caution.")

    parser.add_option_group(ccgrp)
    # add debug option for xmlrpc errors

    opts, args = parser.parse_args(argv)
    # so sanity-chacking stuff here
    if len(args) != 1:
        print "no filename provided"
        parser.print_help()
        sys.exit(1)
    elif not os.path.isfile(args[0]):
        print "%s does not appear to exist, or is not a file."
        parser.print_help()
        sys.exit(2)

    # finally return the cleaned options and args
    return opts, args[0]
        
# --------------------------------------------------------------------------------- #

def get_confchannel_info(rhn, channel_label, verbose=False):
    """
    Processes the specified channels, getting filelists and metadata
    """
    channeldata = configchannel.detailsByLabel(rhn, channel_label)
    filelist = [ x['path'] for x in configchannel.listFiles(RHN, channel_label) ]
    channeldata['files'] = []
    for fentry in configchannel.lookupFileInfo(RHN, channel_label, filelist):
        # we have to handle the ISO datetime stampa - converting to strings
        # we'll probably lose this data on import anyway
        print "processing file %s" % fentry['path']
        fentry['modified'] = str(fentry['modified'])
        fentry['creation'] = str(fentry['creation'])
        channeldata['files'].append(fentry)
    return channeldata
        
# --------------------------------------------------------------------------------- #

def create_config_channel(rhn, chanobj, verbose=False):
    """
    The actual channel creation
    """
    chandata = configchannel.create(rhn, chanobj['label'], chanobj['name'], chanobj['description'])
    if chandata is not False:
        existing_labels.append(chandata['label'])
        return True
        
# --------------------------------------------------------------------------------- #

def add_channel_content(rhn, chanobj, verbose=False):
    """
    Adds a file, directory or symlink to the given configuration file.
    if the object already exists, it will be replaced and its revision number updated.

    returns: True or False

    parameters:
    rhn(rhnapi.rhnSession)      - authenticated RHN session
    chanobj(dict)               - channel object imported from JSON
    fileobj(dict)               - file/dir/symlink object
    verbose(bool)               - be more verbose [False]
    """
    fail_list = []
    for fobj in chanobj['files']:
        objtype = fobj.get('type', 'file')
        objpath = fobj.get('path', 'None')
        if verbose:
            print "adding file %s to config channel" % fobj['path']
        if configchannel.createOrUpdateObject(rhn, chanobj['label'], fobj):
            if verbose:
                print "Added %s %s to channel %s" %(objtype, objpath, chanobj['label'])
        else:
            if verbose:
                print "Failed to add %s %s to channel %s " %(objtype, objpath , chanobj['label'])
            fail_list.append(fobj)
            continue

    # if we have anything in the fail_list, make sure we pass it back to caller
    if len(fail_list) != 0:
        return fail_list
    # else, it must have all worked.
    else:
        return None
        
# --------------------------------------------------------------------------------- #

def update_channel_content(rhn, chanobj, verbose=False):
    """
    simply removes the 'revision' numbers from the file objects, then passes them onto
    'add_channel_content' to use...
    """
    for fobj in chanobj['files']:
        if fobj.has_key('revision'):
            del fobj['revision']

    return add_channel_content(rhn, chanobj, verbose=False)
        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    # process command-line arguments
    opts, inputfile = parse_cmdline(sys.argv[1:])
    # declare this as global as we'll be modifying it in a number of places as we
    # import config channels
    global existing_labels

    try:
        # stuff that does not require an RHN session
        channel_data = utils.loadJSON(inputfile, opts.verbose)
        json_channels =[ x['label'] for x in channel_data ]

        # if we asked for a list, just do that and exit
        if opts.list:
            print "Configuration Channels in file:"
            print '\n'.join(json_channels)
            sys.exit(0)

        # if we specificied a list of channels, process only those:
        if opts.channel:
            channel_list = opts.channel.split(',')
        else:
            if opts.verbose:
                print "no channel specified. importing ALL config channels"
            channel_list = json_channels

        # list of the channel objects from the JSON import that we wish to
        # push to our satellite.
        import_data = [ x for x in channel_data if x['label'] in channel_list ]

        # now we connect to RHN:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)
        if opts.debug:
            RHN.enableDebug()
        # get a list of all existing channels - allows us to check for existing channels.
        existing_labels = [ x['label'] for x in configchannel.listGlobals(RHN) ]

        
        # now walk through our config channel objects...
        # process...
        # 1. does it already exist?
        # 1.5  if y, do we want to replace it?
        #     
        # 2. create the channel
        for chan in import_data:
            if opts.verbose:
                print "Starting import process for Config Channel %s" % chan['label']
            if chan['label'] in existing_labels:
                # okay, the channel already exists, do we want to replace it?
                if opts.replace:
                    print "replacing already existing channel %s" % chan['label']
                    res = configchannel.deleteConfigChannel(RHN, chan['label']) and create_config_channel(RHN, chan)
                    if not res:
                        print "failed to replace existing channel %s" % chan['label']

                # channel exists, we want to update in-place...
                if opts.update:
                    print "Channel %s already exists, updating the files in it" % chan['label']
                # channel exists and we are going to leave it alone...
                else:
                    print "Channel %s already exists, skipping" % chan['label']
                    continue

            else:
                if create_config_channel(RHN, chan):
                    if opts.verbose:
                        print "created config channel %s" % chan['label']
                else:
                    print "could not create configuration channel %s, skipping it" % chan['label']
                    continue

            # now if we get here, our channel should exist...
            if opts.update:
                failed_objects = update_channel_content(RHN, chan, opts.verbose)
            else:
                failed_objects = add_channel_content(RHN, chan, opts.verbose)

            # process our failed objects, if there are any
            if failed_objects is not None:
                rejectsfile = "%s-rejects.json" %(chan['label'])
                if opts.verbose:
                    print "some content could not be uploaded to %s" % chan['label']
                    print "saving rejects to %s" % rejectsfile
                if utils.dumpJSON(failed_objects, rejectsfile):
                    print "Rejects saved to %s" % rejectsfile
                else:
                    print "could not save rejects file. This should not happen."
                    continue

    except KeyboardInterrupt:
        print "Operation Cancelled\n"
        sys.exit(1)



    

