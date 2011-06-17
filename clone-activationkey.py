#!/usr/bin/env python
# -*- coding: utf-8 -*-
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
A script to clone an activation key
simply intended to copy it and all its settings to a new key, which we can then edit.
"""
__author__ = "Your Name <email>"

# standard library imports
import sys
import re
import time
from optparse import OptionParser, OptionGroup
from pprint import pprint

# custom module imports
import rhnapi
from rhnapi import activationkey

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

# --------------------------------------------------------------------------------- #
react_re = re.compile(r'^(Kickstart )?(Reactivation|re-activation) Key.*$', re.I)

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Clone an activation key with all settings intact."
    usagestr = "%prog [RHNOPTS] [KEYOPTS] ACTIVATIONKEY"
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

    keygrp = OptionGroup(parser, "Activation Key Options", "Use these to customise your cloned key. If omitted most will be inherited from the source key")
    keygrp.add_option("-k", "--key", help = "Specify the key (hex code) for the clone. Cannot contain spaces [Autogenerated].")
    keygrp.add_option("-d", "--description", help = "Cloned key description [inherited].")
    keygrp.add_option("-s", "--summary", help = "Cloned key summary [inherited].")
    keygrp.add_option("--list", action = "store_true", default = False, help = "list activation keys and exit")
    parser.add_option_group(keygrp)

    # script-specific options


    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    opts, args = parser.parse_args(argv)

    # expecting an activation key as an argument
    if len(args) == 0 and not opts.list:
        print "no activationkey provided.\n"
        parser.print_help()
        sys.exit(1)

    # finally...
    return opts, args
    
        
# --------------------------------------------------------------------------------- #

def clone_activationkey(rhn, keyobj, description , newkey = '', verbose = False):
    """
    Activation Key Cloning.
    Creates a new key based on the 'keyobj' parameter, then sets any missing elements (packages etc etc)

    parameters:
    rhn(rhnapi.rhnSession)
    keyobj(dict)
    description(str)
    newkey(str)
    verbose(bool)
    """
    if keyobj.get('usage_limit', 0) == 0:
        del keyobj['usage_limit']
    else:
        cloneusage = None

    # create a new activation key from the old one, using our new description and possibly our chosen key:
    newkey = activationkey.create(rhn,
             description,
             newkey,
             keyobj.get('base_channel_label',''),
             keyobj.get('entitlements', []),
             keyobj.get('usage_limit', None),
             keyobj.get('universal_default', False),
             )

    if isinstance(newkey, str):
        if verbose:
            print "Cloned Key %s as %s" %(keyobj['key'], newkey)
        # set child channels
        if len(keyobj.get('child_channel_labels', [])) > 0:
            if activationkey.addChildChannels(RHN, newkey, keyobj.get('child_channel_labels')):
                print "Added Child Channels %(child_channel_labels)r" % keyobj

        # set configuration channels
        if len(keyobj.get('config_channels',[])) > 0:
            if activationkey.setConfigChannels(RHN, [newkey], keyobj.get('config_channels')):
                print "Added Configuration Channels %(config_channels)r" % keyobj

        # set packages
        if len (keyobj.get('packages',[])) > 0:
            print "Adding packages"
            for pkg in keyobj.get('packages'):
                if activationkey.addPackages(RHN, newkey, [ pkg ]):
                    print "  - %s %s" %(pkg.get('name'), pkg.get('arch', '') )

        if len(keyobj.get('server_group_ids', [])) > 0:
            if activationkey.addServerGroups(RHN, newkey, keyobj.get('server_group_ids')):
                print "Added Server Group IDs %(server_group_ids)r" % keyobj

        if keyobj.get('config_deploy', False):
            activationkey.enableConfigDeployment(RHN, newkey)



if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    try:
        # initialise an RHN Session
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # handle debugging requests
        if opts.debug:
            RHN.enableDebug()
        if opts.list:
            print "%-40s   Description" % "Key"
            print "----------------------------------------   ----------------------"
            for akey in activationkey.listActivationKeys(RHN):
                if react_re.search(akey['description']) is None:
                    print "%(key)-40s | %(description)s" % akey
            sys.exit(0)
        else:
            srckey = args[0]

        # process the activation key we have been given
        # basic details
        srcobj = activationkey.getDetails(RHN,srckey)
        # configuration channels in rank order
        srcobj['config_channels'] = [ x['label'] for x in activationkey.listConfigChannels(RHN, srckey) ]
        # config deployment
        srcobj['config_deploy'] = activationkey.checkConfigDeployment == 1

        # now let's create a new key, according to our options:
        # parameters required (from rhnapi.activationkey.create():
        # create(rhn, description, keyid='', basechannel='', entitlements=[], usagelimit=None, universalDefault=False)
        clonekey = opts.key or ''
        clonedesc = opts.description or "%s - Cloned on %s" %(srcobj['description'], time.strftime('%Y%m%d'))

        clone_activationkey(RHN, srcobj, clonedesc, clonekey, opts.verbose)
                


        # DO STUFF with your RHN session and commandline options
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)


    
    
    
