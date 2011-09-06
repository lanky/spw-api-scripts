#!/usr/bin/env python
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
An API script to list duplicate systems based on their hostname.

Written for RHN Satellite v 5.3 as 5.4+ have a direct API call for this.

Uses the python rhnapi module, so make sure that is on your PYTHONPATH
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

# standard library imports
import sys
from optparse import OptionParser, OptionGroup
from operator import itemgetter

# custom module imports
import rhnapi
from rhnapi import system

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Lists duplicate system records (systems with identical names) from your satellite."
    usagestr = "%prog [RHNOPTS]"
    # initialise our parser and set some default options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc)")

    # RHN Satellite options group
    rhngrp = OptionGroup(parser, "RHN Satellite Options", "Defaults can be set in your RHN API config file (%s)" % RHNCONFIG )
    rhngrp.add_option("--server",help="RHN satellite server hostname [%default]", default=RHNHOST)
    rhngrp.add_option("--login", help="RHN login (username)" , default=RHNUSER)
    rhngrp.add_option("--pass", dest = "password", help="RHN password. This is better off in a config file.", default=RHNPASS)
    rhngrp.add_option("--config", dest = "config", help="Local RHN configuration file [ %default ]", default=RHNCONFIG)
    rhngrp.add_option("-C", "--cache", action = "store_true", default = False,
        help = "save usernames and password in config file, if missing")
    parser.add_option_group(rhngrp)

    # script-specific options


    opts, args = parser.parse_args(argv)
    # check the args for errors etc...

    # finally...
    return opts, args
        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    # initialise an RHN Session
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # handle debugging requests
        if opts.debug:
            RHN.enableDebug()
        # DO STUFF with your RHN session and commandline options
        syslist = system.listSystems(RHN)
        sysidx = {}
        for s in syslist:
            k = s['name']
            if sysidx.has_key(k):
                sysidx[k].append(s)
            else:
                sysidx[k] = [ s ]
                        
        dupes = [ x for x in sysidx if len(sysidx.get(x)) > 1 ]
        if len(dupes) > 0:
            print "Duplicate Systems (by name):"
            for s in dupes:
                print "%s" % s
                for record in sorted(sysidx.get(s), key=itemgetter('last_checkin'), reverse=True):
                    print "\t%s [%d]" %( RHN.decodeDate(record['last_checkin']), record['id'] )
                print "----" 
        else:
            print "No duplicate system records found"
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)


    
    
    
