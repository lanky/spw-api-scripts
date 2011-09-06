#!/usr/bin/env python
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
API script template file.
"""
__author__ = "Your Name <email>"

# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup
import logging
# from operator import itemgetter
import rpm
from pprint import pprint
# for reporting
import csv

# custom module imports
import rhnapi
from rhnapi import channel, system, packages, utils

# for progress display:
from progressbar import Counter,Percentage,ProgressBar,Timer,Bar

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
    preamble = """Diffs installed package lists for subscribed systems against a base
software channel and all child channels.
Intended to show systems that have packages installed locally which are not in the
satellite (or are newer than those available from the satellite.)
Needs a base channel label to work with.
"""
    usagestr = "%prog [RHNOPTS] CHANNEL"
    # initialise our parser and set some default options
    parser = OptionParser(usage = usagestr, description = preamble)
    parser.add_option("--debug", action = "store_true", default = False,
            help = "enable debug output for RHN session (XMLRPC errors etc")
    parser.add_option('-v', '--verbose', action = 'store_true', default = False,
            help = "increase verbosity")
    parser.add_option("--progress", action = "store_true", default = False,
        help = "display progressbars")
    parser.add_option("-o","--output", help = "output file for summary info in CSV format")        

    # RHN Satellite options group
    rhngrp = OptionGroup(parser, "RHN Satellite Options", "Defaults can be set in your RHN API config file (%s)" % RHNCONFIG )
    rhngrp.add_option("--server",help="RHN satellite server hostname [%default]", default=RHNHOST)
    rhngrp.add_option("--login", help="RHN login (username)" , default=RHNUSER)
    rhngrp.add_option("--pass", dest = "password", help="RHN password. This is better off in a config file.", default=RHNPASS)
    rhngrp.add_option("--config", dest = "config", help="Local RHN configuration file [ %default ]", default=RHNCONFIG)
    rhngrp.add_option("--logfile", help = "Spool messages to this logfile [stdout]", default = None)
    rhngrp.add_option("--cache", action = "store_true", default = False,
        help = "save usernames and password in config file, if missing")
    parser.add_option_group(rhngrp)


    # script-specific options


    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    opts, args = parser.parse_args(argv)
    # check the args for errors etc...
    if len(args) != 1:
        print "You must provide a channel label as an argument"
        print "see -h or --help for details"
        sys.exit(1)

    # finally...
    return opts, args[0]

# --------------------------------------------------------------------------------- #
        
def setup_logger(logfile, verbose = False):
    """
    Configures logging, returns a logger object
    """
    broken_log = False

    # set up logging
    logger = logging.getLogger(os.path.basename(sys.argv[0]))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    if logfile is None:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)
    else:
        try:
            lf = logging.FileHandler(os.path.expanduser(logfile))
        except IOError:
            lf = logging.StreamHandler()
            broken_log = True
            
        lf.setFormatter(formatter)
        lf.setLevel(logging.DEBUG)
        logger.addHandler(lf)


    # if we increase verbosity and aren't already using a streamhandler to stdout...
    if verbose and isinstance(logger.handlers[0], logging.FileHandler):
        # we also dump data to stdout (info and above only)
        stdout = logging.StreamHandler()
        stdout.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        stdout.setLevel(logging.INFO)
        logger.addHandler(stdout)

    if broken_log:
        logger.error("Cannot open logfile %s. Falling back to standard output" % opts.logfile)

    return logger        

# --------------------------------------------------------------------------------- #

def index_pkgs(packagelist, logger, verbose = False, progressbar = False):
    """
    returns a list of e:nvr.a strings for a given list of package dicts (for example a list of
    packages in a channel or a system record)

    n.b somewhat annoyingly, channel.listLatestPackages uses 'arch_label' where
    system.listPackages uses 'arch' as keys for package architecture,
    so we need to work around this.
    - this turns out to be channel-specific. yay for us.
    """
#    results = []
    if verbose:
        logger.debug("indexing packages by NVREA")
    if progressbar:
        widgets = [ 'Packages: [', Counter(), ']', Bar(), Timer() ]
        pbar = ProgressBar(widgets = widgets, maxval = len(packagelist)).start()
    for p in packagelist:
        # workaround for the clashing key names in system/channel package lists.
        if p.has_key('arch') and not p.has_key('arch_label'):
            p['arch_label'] = p['arch']

        if p['arch_label'] == 'AMD64':
            p['arch_label'] = 'x86_64'

        # if a package has an 'epoch' tag, it goes at the start of an entry.
        # if not, well, it doesn't
        if p.get('epoch').strip() != '':
            p['nvrea'] = "%(epoch)s:%(name)s-%(version)s-%(release)s.%(arch_label)s" % p
        else:   
            p['nvrea'] = "%(name)s-%(version)s-%(release)s.%(arch_label)s"% p

        if verbose:
            logger.debug(p['nvrea'])

        if progressbar:
            pbar.update(packagelist.index(p) + 1)
    if progressbar:            
        # we need to print a newline or the next output overwrites the progressbar.
        # good, huh?
        print            

    return packagelist
# --------------------------------------------------------------------------------- #

def latest_pkg(pkg1, pkg2):
    """
    Compares 2 package objects (dicts) and returns the newest one.
    Comparisons are done using RPM label compares (architecture is not relevant here)
    This is only useful for comparing 2 versions of the same package, or results might
    be a little confusing.
    """
    if pkg1['name'] != pkg2['name']:
        return None
    # okay, now we compare the package info:        
    t1 = (pkg1['epoch'].strip(), pkg1['version'], pkg1['release'])
    t2 = (pkg2['epoch'].strip(), pkg2['version'], pkg2['release'])

    result = rpm.labelCompare(t1, t2)
    if result == 1:
        return pkg1
    elif result == -1:
        return pkg2
    elif result == 0:
        # in this case they are the same
        return pkg1
    else:
        return None

def get_newest_pkg(pkglist, logger = None):
    """
    work through a list of package objects and return the latest version.
    """
    latest = pkglist[0]
    for p in pkglist:
        if latest_pkg(latest, p) == p:
            latest = p
        else:
            continue

    return latest

# --------------------------------------------------------------------------------- #

def compare_pkgs(system_list, channel_pkgs, logger = None):
    """
    parse the list of package diffs
    each system in the system_list has a 'pkgdif' entry, containing 
    """
    # index by name to find packages 
    chan_names = [ p['name'] for p in channel_pkgs ]
    for box in system_list:
        box['missing'] = []
        box['older'] = []
        box['newer'] = []
        for p in box.get('pkgdiff', []):
            # first we list packages on system but NOT in the channel
            if p['name'] not in chan_names:
                box['missing'].append(p['nvrea'])
            else:
                # now we handle older and newer packages in the channel
                # get the list of channel objects that match our current package name
                chanpkg = [ c for c in channel_pkgs if c['name'] == p['name'] ]
                # if this list is more than one item long, we need to find the latest version
                if len(chanpkg) > 1:
                    chan_latest = get_newest_pkg(channel_pkgs)
                    if latest_pkg(p, chan_latest) == p:
                        box['newer'].append(p['nvrea'])
                    elif latest_pkg(p, chan_latest) == chan_latest:
                        box['older'].append(p['nvrea'])
                    else:
                        # this should never happen, but just in case...
                        continue

        m, n, o = len(box.get('missing')), len(box.get('newer')), len(box.get('older'))
        # don't bother reporting on systems with no diffs
        if (m, n, o) == (0,0,0):
            continue
        print "System: %(name)s [%(id)d]" % box
        print "Statistics: missing: %d | newer: %d | older: %d" %(m,n,o)
        if logger is not None:                                                                  
            logger.info("%s [%d] statistics: missing: %d | newer: %d | older: %d" %(box.get('name'), box.get('id'),m,n,o))
        if m > 0:
            print "Installed Packages not in subscribed channels:"
            print ','.join(box.get('missing'))
        if n > 0:
            print "Installed packages NEWER than those in the channel"
            print ','.join(box.get('newer'))
        if o > 0:
            print "Installed packages OLDER than those in the channel"
            print ','.join(box.get('newer'))
        print "-----------------------------------------"

# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    # process commandline arguments 
    opts, chanlabel = parse_cmdline(sys.argv[1:])

    # get a logger instance
    logger = setup_logger(opts.logfile, opts.verbose)

    # initialise an RHN Session
    try:
        logger.info("connecting to RHN Server %s as user %s" %(opts.server, opts.login))
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        satversion = float(RHN.sat_version[0:3])

        # handle debugging requests
        if opts.debug:
            RHN.enableDebug()
            logger.debug("enabling debug for RHN Session id %s" % RHN.key)

        # get a list of existing base channels
        basechannels = channel.listBaseChannels(RHN)
        if chanlabel not in basechannels:
            logger.error("channel label %s is not an existing base channel on your satellite" % chanlabel)

        else:
            # collate a list of child channels for the given base
            if satversion < 5.4:
                logger.info("Satellite Version is %f. Doing things the hard way" % satversion)
                allchannels = [ channel.detailsByLabel(RHN, x['label']) for x in channel.listAllChannels(RHN) ]
                childchans = [ x['label'] for x in allchannels if x['parent_channel_label'] == chanlabel ]
            else:
                childchans = channel.listChildChannels(RHN, chanlabel)

            logger.info("Getting a list of the newest packages available in base channel %s" % chanlabel)
            channelpkgs = channel.listLatestPackages(RHN, chanlabel)
            logger.debug("Retrieved list of %d packages" % len(channelpkgs))
            logger.info("Getting lists of newest packages in child channels")
            for chan in childchans:
                logger.info("Processing %s" % chan)
                childpkgs = channel.listLatestPackages(RHN, chan)
                logger.info("Adding %d packages" % len(childpkgs))
                channelpkgs += childpkgs

            logger.info("indexing package list")
            channelpkgs = index_pkgs(channelpkgs, logger, opts.verbose, False)
            chanidx = set([p['nvrea'].strip() for p in channelpkgs])
            
            # list of subscribed systems in this format:
            # {'selectable': 1, 'id': 1000010885, 'name': 'ukirpb02.uk.tescobank.org'}
            logger.info("Getting a list of systems subscribed to base channel %s" % chanlabel)
            systemlist = channel.listSubscribedSystems(RHN, chanlabel)

            if opts.progress:
                widgets = [ 'Systems [', Counter(), '/ %d]' % len(systemlist), Bar(), Timer() ]
                pbar = ProgressBar(maxval=len(systemlist), widgets = widgets).start()
            for box in systemlist:
                logger.info("listing packages installed on system %(name)s [%(id)d]" % box)
                # fold channel information into our system object:
                box['basechannel'] = system.getSubscribedBaseChannel(RHN, box['id']).get('label')
                box['childchannels'] = ','.join([ x['label'] for x in system.listSubscribedChildChannels(RHN, box['id']) ])
                # list the installed RPM packages from the system record
                syspkgs = system.listPackages(RHN, box['id'])
                # add nvrea tags to each package object
                syspkgs = index_pkgs(syspkgs, logger, opts.verbose, False)
                # ensure there are no duplicates (which there should not be)
                sysidx = set([p['nvrea'].strip() for p in syspkgs])
                # add the package list to our system object
                box['packages'] = syspkgs
                # add the nvrea list of differences (here: packages on system that are not in the channels)
                box['pkgdiff'] = [ p for p in syspkgs if p['nvrea'] in  sysidx.difference(chanidx) ]
                box['last_checkin'] = RHN.decodeDate(box['last_checkin'])

                if opts.progress:
                    pbar.update(systemlist.index(box) + 1 )

            if opts.progress:
                print

            # at this stage our systemlist contains, in each system entry
            # - a full list of installed RPM packages, with nvrea tags
            # - a list of nvrea 
            compare_pkgs(systemlist, channelpkgs, logger)
            if opts.output:
                utils.csv_report(systemlist, opts.output, fields = ['name', 'id', 'missing', 'newer', 'older', 'basechannel', 'childchannels', 'last_checkin'])



                

            


        # DO STUFF with your RHN session and commandline options
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)


    
    
    
