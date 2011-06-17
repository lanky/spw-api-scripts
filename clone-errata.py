#!/usr/bin/env python
# -*- coding: utf-8 -*-
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
clone-errata.py
An errata cloning/publishing script intended to
1. take a list of errata and channel labels
2. *clone* RH errata into one channel
   - then publish the clones into the other channels
3. publish the non-RH errata into all selected channels.

Currently no checking if an erratum has already been cloned

for specific packages you can get lists of providing errata
using the list-errata-for-package.py script
"""
# standard library imports
import sys
from optparse import OptionParser, OptionGroup
import re

# custom module imports
import rhnapi
from rhnapi import errata

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None


# --------------------------------------------------------------------------------- #
rh_pattern = re.compile('^RH(SA|BA|EA)-.*')
# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Clone the specified list of errata (or publish already cloned errata) from one channel to another"
    usagestr = "%prog [RHNOPTS] -c CHANNEL ERRATUM..."
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

    # option group for non-generic options
    errgrp = OptionGroup(parser, "Errata and Channel Options")
    errgrp.add_option("-c", "--channel",
        help="Channel LABEL to clone or publish errata to. Can be a comma-separated list. No spaces")
    parser.add_option_group(errgrp)


    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    opts, args = parser.parse_args(argv)
    # check the args for errors etc...

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #
if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    # initialise an RHN Session
    # safety mechanism until the script actually works:
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()
        channel_list = opts.channel.split(',')
        errata_list = args

        clone_list = []
        publish_list = []
        for erratum in errata_list:
            if rh_pattern.match(erratum):
                clone_list.append(erratum)
            else:
                publish_list.append(erratum)
        print "Errata to clone: ", clone_list
        print "Errata to publish", publish_list
        # so, first we clone into our first channel, then publish into any others
        if len(clone_list) != 0:
            # okay, if we have more than one destination channel
            # clone the list of RH errata into our first channel
            # this takes a single channel and a list of errata.
            clonedest = channel_list[0]
            print "cloning Red Hat errata into %s" % clonedest
            
            # keep a list for publishing later:
            new_clones = errata.clone(RHN, clonedest, clone_list)
            # publish these into the remaining channels
            # we have more than one channel to clone/publish into...
            if len(channel_list) > 1:
                if opts.verbose:
                    print "publishing newly cloned errata into other selected channels"
                for erratum in [ x['advisory_name'] for x in new_clones ]:
                    errata.publish(RHN, erratum, channel_list[1:])

            # now just publish all the other errata into all selected channels
            # this is done one erratum at a time, to multiple channels
        if len(publish_list) != 0:
            for erratum in publish_list:
                if opts.verbose:
                    print "publishing previously cloned erratum %s into selected channels" % erratum,
                data = errata.publish(RHN, erratum, channel_list)
                if type(data) == dict:
                    if opts.verbose:
                        print " ...complete"
    
    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)
