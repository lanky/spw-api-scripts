#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to dump a kickstart profile to JSON
__doc__ = """
A script to dump activation keys to JSON format, allowing import on another server with the companion json2kickstart script.
tested on satellite 5.4, but still considered beta. Backup your satellite DB before using it.

What it saves:
* activation keys
* system groups (by ID and name)
* config channels
* software channels

These items should exist on the destination satellite before you attempt to import a key that uses them.
"""

# standard library imports
import sys
from optparse import OptionParser, OptionGroup
import simplejson
from pprint import pprint
# for timestamps in filenames
import time
import re

# custom module imports. Make sure they're on your PYTHONPATH :)
import rhnapi
from rhnapi import kickstart
from rhnapi import activationkey
# this needs editing to add the ID->name functionality:
from rhnapi import systemgroup
# utility functions, including JSON management
from rhnapi import utils

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

# if we want to exclude reactivation keys (we probably do), this is a simple
# regex pattern that matches their descriptions.
react_pattern = re.compile(r'^(Kickstart )?(Reactivation|re-activation) Key.*$', re.I)

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Dump all (or a list of) existing activation keys to a JSON-format text file"
    usagestr = "%prog [RHNOPTS] [OTHEROPTS]"
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
    keygrp = OptionGroup(parser, "Activation Key options", "Options for processing Activation Keys")
    keygrp.add_option("--list", action = "store_true", default = False, help = "List activation keys and exit")
    keygrp.add_option("-a", "--all", action = "store_true", default = False, help = "dump data for ALL activation keys profiles")
    keygrp.add_option("-f", "--file", help = "filename to dump activation key information to [KICKSTARTLABEL.json or activationkeys.json]")
    keygrp.add_option("-k", "--key", help = "Activation Key (the hyphenated 'hex string'). Can also take a comma-separated list. No spaces.")
    keygrp.add_option("-r", "--reactivation-keys", action = "store_true", default = False, help = "Include Reactivation keys if exporting all keys [%default]")
    keygrp.add_option("-s", "--stdout", action = "store_true", default = False,
        help = "Don't use an export file, just print the data.")
    parser.add_option_group(keygrp)


    opts, args = parser.parse_args()
    if not opts.list and not opts.key and not opts.all:
        print "You must provide either an activationkey (or --all) or the --list option"
        parser.print_help()
        sys.exit(1)


    # check the args for errors etc...

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #

def get_key_details(rhn, keyobject, verbose = False):
    """
    Extracts the relevant data from your satellite for a given activation key and
    blends it into a dict structure.

    parameters
    rhn                - authenticated rhnapi.rhnSession object
    keyobject(dict)    - entry from activationkey.listActivationKeys
    """
    keyname = keyobject['key']
    keyobject['config_channels'] = activationkey.listConfigChannels(rhn, keyname)
    keyobject['config_deploy'] = activationkey.checkConfigDeployment(rhn, keyname)
    if len(keyobject['server_group_ids']) != 0:
        keyobject['server_groups'] = get_group_details(rhn, keyobject['server_group_ids'])

    return keyobject
        
# --------------------------------------------------------------------------------- #

def get_group_details(rhn, groupids, verbose = False):
    """
    Call out to rhnapi.systemgroup to get group details for each group in groupids
    This is because groupname->id pairs differ between satellites.
    We're going to fetch the group names instead (well, all group details, actually)
    """
    results = []
    for grp in groupids:
        grpdetails = systemgroup.getDetails(rhn, grp)
        # grpdetails should never be false - we got the groupid from this server, after all
        # still, for safety...
        if grpdetails != False:
            results.append(grpdetails)
    return results

# --------------------------------------------------------------------------------- #

def keytable(keylist):
    """
    Print a table of the description/key pairs in keytable
    """
    if len(keylist) == 0:
        print "(No Activation Keys found)"
        return False
    print "%-36s %s" %("Activation Key", "Description")
    print "-----------------------------------  ------------------------------------"
    for keyobj in keylist:
        print "%(key)-36s %(description)s" % keyobj


        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':

    opts, args = parse_cmdline(sys.argv)
    # initialiase an RHN Session
    # print "This is under heavy development and is currenttly non-functional"
    # sys.exit(0)
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()

        all_keys = activationkey.listActivationKeys(RHN)
        key_names = [ x['key'] for x in all_keys ]
        # we're going to dump as a list of dict.
        export_data = []

        if not opts.reactivation_keys:
            if opts.verbose:
                print "Removing reactivation keys from our key list"
            all_keys = [ x for x in all_keys if not react_pattern.match(x['description'])]

        if opts.list:
            print "Activation Keys on your satellite"
            if not opts.reactivation_keys:
                print "(Reactivation Keys Excluded)"
            keytable(all_keys)
            sys.exit(0)

        if opts.key:
            for akey in opts.key.split(','):
                if akey in key_names:
                    keydata = [ x for x in all_keys if x.get('key') == akey ][0]
                    export_data.append(get_key_details(RHN, keydata, opts.verbose))
                else:
                    print "cannot locate Activation Key %s, does it really exist?" % kslabel
                    print "skipping for the time being"
                    continue

        if opts.all:
            if opts.verbose:
                print "processing all Activation Keys. This could take a while"
            for keyobject in all_keys:
                print "processing Activation Key %s (%s)" % (keyobject['description'], keyobject['key'])
                export_data.append(get_key_details(RHN, keyobject, opts.verbose))
        if opts.stdout:
            pprint(export_data)
            sys.exit(0)
        if opts.file:
            outputfile = opts.file
        else:
            tstamp = time.strftime('%Y%m%d_%H%M')
            if opts.all:
                outputfile = 'activationkey-export-%s.json' % tstamp
                if opts.verbose:
                    print "no filename provided, exporting all keys to %s" % outputfile
            elif opts.key:
                outputfile = '%s.json' % (opts.key.split(',')[0])
                if opts.verbose:
                    print "no filename provided, using the first key selected (%s)" % outputfile
        if len(export_data) != 0:
            # dump_to_file(outputfile, export_data, opts.verbose)
            utils.dumpJSON(export_data, outputfile, verbose = opts.verbose)
        else:
            print "None of the chosen Activation Keys could be successfully dumped."
            sys.exit(1)



    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)





