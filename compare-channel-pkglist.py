#!/usr/bin/env python
# -*- coding: utf-8 -*-
# RHN XMLRPC API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
Compares a textdump of 'rpm -qa' from a system to a channel in RHN
the rpm -qa output should look like this:
NAME|VERSION|RELEASE|ARCH|EPOCH

so set your --queryformat appropriately
e.g. rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}\n'

The separator for these fields can be specified on the commandline.
"""
# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup
from pprint import pprint

# custom module imports
import rhnapi
from rhnapi import packages
from rhnapi import channel
from rhnapi import utils

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
    preamble = """Reads a textfile containing a dump of rpm -qa from a system with a channel in RHN Satellite.
 The rpm queryformat should contain NAME|VERSION|RELEASE|ARCH|EPOCH information.
 Separator can be any reasonable char but defaults to the pipe character. """
    usagestr = "%prog [RHNOPTS] [-f OUTPUTFILE ] [ -S SEPARATOR ] -c CHANNEL_LABEL INPUTFILE"
    parser = OptionParser()
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
    changrp.add_option("-c", "--channel", help = "Channel LABEL to diff against.")
    changrp.add_option("-f", "--file", help = "output file for diffs")
    changrp.add_option("-S", "--separator", default = "|",
        help = "separator used in rpm -qa queryformat. default is "%default"")
    parser.add_option_group(changrp)

    # parse the arguments we were given (commandline, probably)
    opts, args = parser.parse_args(argv)

    # check the args for errors etc...
    if len(args) != 1:
        parser.print_help()
        sys.exit(0)
    else:
        if not os.path.isfile(args[0]):
            print "input file %s does not exist" % args[0]
            parser.print_help()
            sys.exit(1)
    # only expecting one arg, so let's just return that instead of a list            
    return opts, args[0]

# --------------------------------------------------------------------------------- #

def main():
    # there should only be one entry in args, so...
    opts, inputfile = parse_cmdline(sys.argv[1:])
    outputfile = inputfile.replace('.txt','.json')
    try:
        # initialise an RHN Session
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # while in development:
        if opts.debug:
            RHN.enableDebug()
        filepkgs = []
        for line in open(inputfile):
            try:
                # lines should be name|ver|rel|arch|epoch, where epoch is mostly '(none)'
                pkgname, pkgver, pkgrel , pkgarch, pkgepoch = line.split(opts.separator)
                if pkgepoch.strip() == '(none)':
                    pkgepoch = ''
            except:
                # ignore lines not matching the pattern
                continue

            pkgdetails = packages.findByNvrea(RHN, pkgname, pkgver, pkgrel , pkgarch, pkgepoch)

            if pkgdetails:
                filepkgs.append(pkgdetails)

        print "dumping to %s " % outputfile
        utils.dumpJSON(filepkgs, outputfile)

    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)

# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    main()
    


    
    
    
