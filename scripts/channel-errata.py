#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append

__doc__ = """
channel-errata.py
A script to summarise the available errata for your cloned channels, in their source channel.
Requires the use of a configuration file in .ini format, with sections like this:
[channel-label]
source = source-channel-label
errata = ALL

where errata can be a comma-separated list of these:
security    - for security announcements
bugfix      - for bug fix errata
enhancement - for new features.

channels not in your config file will not be processed (as we don't know where
they were cloned from)

Requires the rhnapi python module somewhere on your pythonpath.
and the 'progressbar' module.
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup
from ConfigParser import SafeConfigParser
from operator import itemgetter

# custom module imports
import rhnapi
from rhnapi import channel, errata, utils

# from utils.progressbar import ProgressBar

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None

# configuration for channel mappings and output.
SYSCONFIG = [ '/etc/sysconfig/channel-mappings.conf']
LOCALCONFIG = os.path.expanduser('~/.rhn-channels.conf')
# should we stick this in a configfile too?
MAXLENGTH = 40

from progressbar import Counter,Percentage,ProgressBar, Timer, AnimatedMarker, Bar

# --------------------------------------------------------------------------------- #
# for ease of configuration:
errmap    = {'security' : 'Security Advisory', 'bugfix'   : 'Bug Fix Advisory', 'enhancement' : 'Product Enhancement Advisory'}

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Compares a cloned channel to its source and lists unsynced errata for review"
    usagestr = "%prog [RHNOPTS] [CHANNELOPTS]"
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
    changrp = OptionGroup(parser, "Channel and config options")
    changrp.add_option("-f", "--file", help = "cloned channel mapping file. Overrides defaults [%s, %s]" %(LOCALCONFIG, SYSCONFIG))
    changrp.add_option("-c", "--channel", help = "channel LABEL to check. by default ALL channels in your config file are summarised")
    changrp.add_option("-t", "--errata-type", choices = ["security", "bugfix", "enhancement", "ALL" ], 
        help = "Errata type to show. Overrides configuration. valid choices: security, bugfix, enhancement, ALL")
    changrp.add_option("--relevant", action = "store_true", default = False,
        help="Only show unsynced errata that apply to one or more systems")
    changrp.add_option("-l","--list", action = "store_true", default = False,
        help = "list channels and settings from config file and exit")
    changrp.add_option("--csv", action = "store_true", default = False,
        help = "dump output in csv format")
    changrp.add_option("--json", action = "store_true", default = False,
        help="dump output in JSON format (for testing)")
    changrp.add_option("-o", "--output", help = "output filename. Will be overwritten if it already exists")
    parser.add_option_group(changrp)



    opts, args = parser.parse_args(argv)
    # check the args for errors etc...

    if (opts.json or opts.csv) and not opts.output:
        print "cannot dump to JSON or CSV without an output file!"
        parser.print_help()
        sys.exit(1)

    # finally...
    return opts, args
        
# --------------------------------------------------------------------------------- #

def load_config(configlist, verbose = False):
    """
    Instantiates a configparser instance and populates it
    """
    parser = SafeConfigParser()
    try:
        parser.read(configlist)
        return parser
    except:
        print "could not load configfile %s" % configfile
        sys.exit(1)

# --------------------------------------------------------------------------------- #

def get_missing_errata(rhn, chan, source, errtype, verbose = False):
    """
    returns a list of errata of the given type that have not yet been cloned into the given channel.
    """
    e = errmap.get(errtype)
    chanerrata  = set([x.get('advisory') for x in channel.listErrataByType(rhn, chan, e)])
    srcerrata   = set([x.get('advisory') for x in channel.listErrataByType(rhn, source, e)])
    diff = srcerrata.difference(chanerrata)
    if len(diff) > 0:
        return list(diff)
    else:
        return []

# --------------------------------------------------------------------------------- #

def get_packages(rhn, chan, advisory):
    """
    returns a list of the packages from our source channel that are provided by an erratum
    """
    return ([ x for x in errata.listPackages(rhn, advisory) if chan in x['providing_channels']])

# --------------------------------------------------------------------------------- #

def summarise(data):
    """
    takes the channeldata list and summarises it with a nice little titlebar :)
    """
    for chanobj in sorted(data, key=itemgetter('channel')):
        print "Channel: %(channel)s Source: %(source)s" % chanobj
        for etype, buglist in chanobj.get('errata').iteritems():
            print "Errata Type: %s" % errmap.get(etype)
            print "===================================================="
            print "%-15s %-10s %-40s %s" %("Advisory", "Rating", "Synopsis", "Packages")
            print "=============== ========== ======================================== ======================"

            for bugobj in sorted(buglist, key = itemgetter('advisory')):
                print "%(advisory)-15s %(rating)-10s %(synopsis)-40s %(packages)s" % bugobj

            print
        print "==============================================="



# --------------------------------------------------------------------------------- #

def dump_csv(data):
    """
    dumps data as CSV with a header line
    """
    pass

# --------------------------------------------------------------------------------- #

def process_erratum(rhn, advisory, etype, maxlength = MAXLENGTH):
    """
    processes each erratum by advisory name to extract the data we require.
    Returns a dict for each
    parameters:
    rhn                 - authentication rhnapi.rhnSession
    advisory(str)       - advisory name (RHSA...)
    etype(str)          - advisory type (security, bugfix, enhancement)
    maxlength(int)      - max length of synopsis
    """
    entry = {'advisory' : advisory}
    entry['packages'] = get_packages(rhn, source, name)
    if etype == 'security':
        entry['rating'], synopsis = errata.getDetails(rhn, name).get('synopsis').split(':')
        entry['synopsis'] = synopsis.strip()
    else:
        entry['rating'] = '-'
        synopsis = errata.getDetails(rhn, name).get('synopsis')
        entry['synopsis'] = synopsis.strip()
    entry['bugs'] = errata.bugzillaFixes(rhn, name).keys()
    entry['systems'] = errata.listAffectedSystems(rhn, advisory)
    return entry

# --------------------------------------------------------------------------------- #

def pretty_print(data, verbose = False, relevantonly = False):
    """
    more verbose summary for a bug report
    returns a list of lines that can be either dumped to stdout (aka 'print')
    or written to a file handle (or both, I supposed)
    """
    lines = []
    for chanobj in sorted(data, key=itemgetter('channel')):
        lines.append("Channel: %(channel)s Source: %(source)s\n" % chanobj)
        lines.append("====================================================\n")
        for etype, buglist in chanobj.get('errata').iteritems():
            lines.append("Errata Type: %s\n" % errmap.get(etype))
            if relevantonly:
                lines.append("**Relevant** Unsynced Errata: %d\n" % len(buglist))
            else:
                lines.append("Unsynced Errata: %d\n" % len(buglist))
            lines.append("----------------------------------------------------\n")
            for bugobj in sorted(buglist, key = itemgetter('advisory')):
                lines.append("Advisory: %(advisory)s\n" % bugobj)
                if etype == 'security':
                    lines.append("Rating: %(rating)s\n" % bugobj)
                lines.append("Synopsis:\n")
                lines.append("\t%(synopsis)s\n" % bugobj)
                if verbose:
                    lines.append("Packages:\n")
                    for pkg in bugobj.get('packages'):
                        pkg['summary'] = pkg.get('summary').strip()
                        lines.append("\t%(name)s-%(version)s-%(release)s.%(arch_label)s - %(summary)s\n" % pkg)
                else:
                    lines.append("Packages: %d\n" %len(bugobj.get('packages')))
                if len(bugobj.get('systems')) > 0:
                    if verbose:
                        lines.append("Affected Systems:\n")
                        for box in bugobj.get('systems'):
                            lines.append("\t%(name)s [id: %(id)d]\n" % box)
                    else:
                        lines.append("Affected Systems: %d\n" % len(bugobj.get('systems')))
                else:
                    lines.append("Affected Systems: None\n")
                lines.append("----------------------------------------------------\n")
        lines.append("====================================================\n\n")
    return lines                    

# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])

    if opts.file:
        config = load_config([opts.file], opts.verbose)
    else:
        config = load_config([LOCALCONFIG, SYSCONFIG], opts.verbose)

    if opts.list:
        print "Channel Configuration Settings"
        print "------------------------------"
        for chan in config.sections():
            print "Channel Label:  %s" % chan
            print "Source Channel: %s" % config.get(chan, 'source')
            print "Errata Types:   %s" % config.get(chan, 'errata')
            print "-------------------"
        sys.exit(0)

    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # handle debugging requests
        if opts.debug:
            RHN.enableDebug()
        # run through our config file for channel mappings and summarise
        # section headers are channel labels:
        channeldata = []
        if opts.channel:
            chanlist = opts.channel.split(',')
        else:
            chanlist = config.sections()
        for chan in chanlist:
            if not config.has_section(chan):
                print "no configuration for channel %s, skipping" % chan
                continue
            source = config.get(chan, 'source')
            if opts.errata_type:
                errtypes = [ opts.errata_type ]
            else:
                errtypes = [ x.strip() for x in config.get(chan, 'errata').split(',')]
            if 'ALL' in errtypes:
                errtypes = ['security', 'bugfix', 'enhancement']
            print "channel %s cloned from %s" %(chan, source)
            summary = {'channel' : chan, 'source' : source, 'errata' : {} }
            for etype in errtypes:
                buglist = []
                # collate our unsynced errata
                enames = get_missing_errata(RHN, chan, source, etype)
                # wrap it in a progressbar
                widgets = [etype, ': ', Counter(), ' Errata [', Percentage(), ']', Bar(), '(', Timer(), ')']
                pbar = ProgressBar(widgets=widgets, maxval=len(enames), term_width=80).start()
                for name in enames:
                    progress = enames.index(name) + 1
                    entry = process_erratum(RHN, name, etype)
                    pbar.update(progress)

                    if opts.relevant:
                        if len(entry['systems']) > 0:
                            buglist.append(entry)
                        else:
                            continue
                    else:
                        buglist.append(entry)
                pbar.finish()
                print
                
                summary['errata'][etype] = buglist
            channeldata.append(summary)

            # pretty_print(channeldata)
            if opts.json:
                if opts.output:
                    utils.dumpJSON(channeldata, opts.output)
                
            else:
                lines = pretty_print(channeldata, opts.verbose, opts.relevant)
                if not opts.output:
                    outfile = sys.stdout
                else:
                    try:
                        outfile = open(opts.output, 'wb')
                    except:
                        print "unable to open %s" % opts.output
                        sys.exit(2)

                outfile.writelines(lines)
                        


                            

            
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)

"""
[ { 'channel': 'aegon-rhel-as-4.9-base-x86_64',
    'source': 'rhel-x86_64-as-4',
    'security' : [
        { 'advisory': 'RHSA-...',
          'packages' : 'package1,package2...'
          'bugs' : 'bug1,bug2,bug3...'
        },
        {...},
        ...
     ]
     'bugfix' : ...
         }
    'systems' : [...]
  }
]  
                      
"""
    
    
    
