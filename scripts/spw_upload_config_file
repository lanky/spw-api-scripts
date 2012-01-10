#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script for uploading config files to a configuration channel.

import sys
import os
from optparse import OptionParser, OptionGroup
# Custom RHN Api Module
import rhnapi
from rhnapi import configchannel

__doc__ = """
upload config files/directories to a given config channel
"""

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

ent_maps = { 'provisioning_entitled' : 'provisioning',
             'monitoring_entitled' : 'monitoring',
             'virtualization_host' : 'virt',
             'virtualization_platform' : 'virt-platform',
}



# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Upload the given file to a configuration channel in your satellite. Default values in [] brackets"
    usagestr = "%prog [RHNOPTS] [CONFIGFILEOPTS]"
    # initialise our parser and set some default options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
        help = "enable debug output for RHN session (XMLRPC errors etc")
    parser.add_option('-v', '--verbose', action = 'store_true', default = False,
        help = "increase verbosity")
    parser.add_option('-i' ,'--interactive', action='store_true', default='False',
        help='Prompt for missing required parameters')

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
    confgrp = OptionGroup(parser, "Config File Options", "Options controlling files to upload and their content")
    confgrp.add_option('-c', '--channel', help='Configuration Channel label (required)')
    confgrp.add_option('-p', '--path', help='path for deployment')
    confgrp.add_option('-f', '--file', help='file to open for content. Must be readable by the current user.')
    confgrp.add_option('-o', '--owner', help='Owner of file [ %default ]', default='root')
    confgrp.add_option('-g', '--group', help='Group of file [ %default ]', default='root')
    confgrp.add_option('-m','--perms', help='octal permissions (e.g. 0770) for this file [ %default ]', default='0644')
    confgrp.add_option('-Z', '--context', help='SELinux security context (partial is okay. not required)')
    confgrp.add_option('--macro-start', help='Macro start delimeter [ "%default" ]', default='{|')
    confgrp.add_option('--macro-end', help='Macro end delimeter [ "%default" ]', default='|}')
    parser.add_option_group(confgrp)


    opts, args = parser.parse_args()
    # check the args for errors etc...
    if not opts.file:
        print "You must supply a filename for me to read content from!"
        sys.exit(1)

    # ask for missing label, if we are in interactive mode
    if not opts.channel and opts.interactive:
        print "Missing required parameter (channel label)"
        opts.channel = prompt_missing("Channel Label: ")

    # ask for missing path, if we are in interactive mode
    if not opts.path and opts.interactive:
        print "Missing Required parameter (path)"
        prompt_missing("Path (when deployed): ")

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #
def prompt_missing(promptstr):
    """
    prompt for a missing element
    """
    return str(raw_input(promptstr))
# --------------------------------------------------------------------------------- #
def prompt_confirm(action, default='Y'):
    """
    prompt for a yes/no answer to an action
    """
    ans = raw_input('Really %s [%s]? ' %(action, default))
    if str(ans).lower() == default.lower():
        return True
    else:
        return False
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv)

    # initialiase an RHN Session
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)

        RHN.enableDebug()
        # DO STUFF
        existing_chans = [ x['label'] for x in configchannel.listGlobalChannels(RHN) ]
        
        if opts.channel not in existing_chans:
            print "That channel does not exist. The config channels on your satellite are:"
            print '\n'.join(existing_channels)

        try:
            if opts.verbose:
                print "reading content from file %s" % opts.file
            data = open(opts.file).read()
        except OSError:
            print "could not open file %s to fetch contents" % opts.file
            sys.exit(2)
        if opts.verbose:
            print "uploading config file data to config channel %s" % opts.channel

        filedata = configchannel.createOrUpdatePath(RHN, label = opts.channel, path = opts.path,
                                         content = data, owner = opts.owner, group = opts.group,
                                         perms = opts.perms, context = opts.context,
                                         isdir=False, macro_start=opts.macro_start, macro_end=opts.macro_end)
        print "file %s created/updated. Now at revision %d" %( filedata['path'], filedata['revision'])
        

    # handles a ctrl-c interrupt:
    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)


    
    
    
