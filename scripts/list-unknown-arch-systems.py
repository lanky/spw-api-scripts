#!/usr/bin/env python
# -*- coding: utf-8 -*-
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
API script template file.
"""
# standard library imports
import sys
from optparse import OptionParser, OptionGroup
from operator import itemgetter
import time

# custom module imports
import rhnapi
from rhnapi import system

# progressbar
from utils.progressbar import ProgressBar


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
    preamble = """Lists systems whose satellite profile has packages marked of 'unknown' architecture.
This is an artifact seen on older RHEL4 systems."""
    usagestr = "%prog [RHNOPTS]"
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

    opts, args = parser.parse_args(argv)
    # check the args for errors etc...

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #

def pretty_system_list(syslist, sortkey, reverse=False):
    """
    prints a systemlist sorted by a given key
    """
    for system in sorted(syslist, key = itemgetter(sortkey), reverse = reverse):
        lcheck = time.strftime('%Y-%m-%d %H:%M:%S', time.strptime(str(system['last_checkin']), '%Y%m%dT%H:%M:%S'))
        print "%-12d %-22s %-18s %s" %(system['id'], system['name'], lcheck, system['base_channel'])



# --------------------------------------------------------------------------------- #
if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    # initialise an RHN Session
    # safety mechanism until the script actually works:
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # more fully-featured debug info
        if opts.debug:
            RHN.enableDebug()

        systemlist = system.listSystems(RHN)
        failed_systems = []
        
        pbar = ProgressBar(0, len(systemlist) + 1, 77, mode='fixed', char='#')
        oldbar = str(pbar)
        
        print "Checking all systems for packages with arch 'Unknown'"
        counter = 1
        for box in systemlist:
            count = systemlist.index(box)
            for pkg in system.listPackages(RHN,box['id']):
                if pkg['arch'] == 'Unknown':
                    box['base_channel'] = system.getBaseChannel(RHN, box['id'])
                    failed_systems.append(box)
                    break
            pbar.update_amount(count)
            if oldbar != str(pbar):
                print pbar, '\r',
                sys.stdout.flush()
                oldbar = str(pbar)
        print 

        if len(failed_systems) > 0:
            print "Systems that require re-registration"
            print "System ID    System Name            Last Checkin Date  Base Software Channel"
            print "----------   --------------------   -----------------  ---------------------"
            pretty_system_list(failed_systems, 'name', reverse=False)

    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)


    
    
    
