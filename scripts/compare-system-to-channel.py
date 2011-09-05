#!/usr/bin/env python
# -*- coding: utf-8 -*-
# template API script using the rhnapi python module
# the module will need to be on your PYTHONPATH
# or its parent directory added using sys.path.append
"""
compare-system-to-channel.py
A script to diff the package list from a server and the packages in
its subscribed base channel to see what is missing (or has been updated
out-of-band)
Can also diff with another selected channel if required.

requires the rhnapi python module.
"""
# standard library imports
import sys
import os
from optparse import OptionParser, OptionGroup
from operator import itemgetter
from pprint import pprint
import rpm

# custom module imports
import rhnapi
from rhnapi import system
from rhnapi import channel
from rhnapi import packages
from rhnapi import utils

from progressbar import Counter,Percentage,ProgressBar, Timer, AnimatedMarker, Bar


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
    preamble = """processes all systems with the chosen base channel.
Returns a list of all packages on the system but not in the base channel,
plus any errata that provide those packages (if there are any)."""
    usagestr = "%prog [RHNOPTS...] [SYSTEMOPTS...]"
    # initialise our parser and set some default options
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

    # script-specific options
    sysgrp = OptionGroup(parser, "System and Channel selection")
    sysgrp.add_option("-o", "--output", default = None, help = "output data to this filename as JSON, for later use")
    sysgrp.add_option("-p", "--profile", default = None, help = "only process this system profile name.")
    sysgrp.add_option("-c", "--channel", default = None,
        help="channel name to diff against. Optional - only if not the system's current base channel")
    sysgrp.add_option("-a", "--all", dest = "consolidate", default = False, action = "store_true",
        help = "just summarize all provided systems, not one at a time")
    parser.add_option_group(sysgrp)

    # this is quite a long-running script, so offer to show a progressbar if needed.
    parser.add_option("-q", "--quiet", action = "store_true", default = False,
            help = "hide output (progressbars etc). Conflicts with -d/--debug.")

    opts, args = parser.parse_args()
    # check the args for errors etc...
    if not opts.channel and not opts.profile:
        print "you must provide either a system profile name or a channel label."
        parser.print_help()
        sys.exit(1)

    if opts.quiet and opts.debug:
        print "you have specified both --quiet and --debug. You can't have it both ways!"
        parser.print_help()
        sys.exit(1)

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #
def get_pkgids(rhn, packagelist, progressbar = True):
    """
    As system.listPackages doesn't give package IDs, I need to search for each pkg
    using findByNvrea
    This shows a progressbar by default
    """
    if progressbar:
        widgets = ['Getting Package Details: ', Counter(), ' packages [', Percentage(), ']', '(', Timer(), ')']
        pbar = ProgressBar(widgets=widgets, maxval=len(packagelist), term_width=80).start()
    for pkg in packagelist:
        if progressbar:
            count = packagelist.index(pkg) + 1
        # handle AMD64 as an arch label (why does satellite not handle this automatically?)
        if pkg['arch'].strip() == 'AMD64':
            arch = 'x86_64'
        else:
            arch = pkg['arch']
        searchdata = packages.findByNvrea( rhn, pkg['name'], pkg['version'], pkg['release'], arch, pkg['epoch'])
        if len(searchdata) != 1:
            continue
        else:
            pkginfo = searchdata[0]
        if isinstance(pkginfo, dict):
            for k, v in pkginfo.iteritems():
                if pkg.has_key(k):
                    continue
                else:
                    pkg[k] = v
        if progressbar:
            pbar.update(count)
    # print
    return packagelist

# --------------------------------------------------------------------------------- #
def check_unknown(pkglist):
    """
    returns True if there are no packages of 'unknown' arch in a package list.
    (handles old broken versions of up2date)
    """
    for x in pkglist:
        if x['arch'].lower() == 'unknown':
            return False
    return True

# --------------------------------------------------------------------------------- #
def diff_package_lists(system_pkgs, channel_pkgs):
    """
    Take 2 package lists and calculate stuff in pkglist1 not in pkglist 2
    Specifically this will include updates beyond the channel update level
    """
    pkgs1 = set([ x['id'] for x in system_pkgs if x.has_key('id') ])
    pkgs2 = set([ x['id'] for x in channel_pkgs if x.has_key('id')])
    pkgdiffs = [ x for x in system_pkgs if x.has_key('id') and x['id'] in pkgs1.difference(pkgs2) ]
    return pkgdiffs

# --------------------------------------------------------------------------------- #

def latest_pkg(pkg1, pkg2):
    """
    Compares 2 package objects (dicts) and returns the newest one.
    Comparisons are done using RPM label compares (architecture is not relevant here)
    This is only useful for comparing 2 versions of the same package, or results might
    be a little confusing.
    """
    # Sometimes empty epoch is a space, and sometimes its an empty string, which 
    # breaks the comparison, strip it here to fix
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

# --------------------------------------------------------------------------------- #

def index_by_arch(pkglist, progressbar = False, verbose = False):
    """
    returns an index of the given package list (for ease of reduction)
    extend this for
    { 'name' : { 'arch' : [], 'arch' :[] ] ?
    """
    pkgindex = {}
    if progressbar:
        widgets = ['Indexing packages by architecture: ', Counter(), ' packages [', Percentage(), ']', '(', Timer(), ')']
        pbar = ProgressBar(widgets=widgets, maxval=len(pkglist), term_width=80).start()
    if verbose:
        print "indexing package list (%d items) by name and architecture" % len(pkglist)
    for pkg in pkglist:
        name = pkg['name']
        arch = pkg['arch_label']

        # ensure there is an entry for this package name
        if not pkgindex.has_key(name):
            pkgindex[name] = {}
        # if there isn't an appropriate arch subkey, create that too
        if not pkgindex[name].has_key(arch):
            pkgindex[name][arch] = []

        pkgindex[pkg['name']][pkg['arch_label']].append(pkg)
        if progressbar:
            pbar.update(pkglist.index(pkg) +1)
    if verbose:
        print "indexed %d packages" % len(pkgindex)
    return pkgindex

# --------------------------------------------------------------------------------- #

def reduce_by_arch(pkglist, progressbar = False, verbose = False):
    """
    returns a reduced package list, containing the latest version of any package for each architecture.
    (i.e. if zsh is in the channel both in i386 and x86_64 arches, returns the latest version for each.
    Which should really be the same, but just in case...)
    """
    # first, index the package list by name for ease of comparison:
    pkgindex = index_by_arch(pkglist, progressbar = progressbar, verbose = verbose)

    reduced_list = []
    if verbose:
        print "reducing package list (%d items) to latest versions only (for each architecture)" % len(pkglist)
    if progressbar:
        widgets = ['Reducing package list to latest versions: ', Counter(), ' packages [', Percentage(), ']', '(', Timer(), ')']
        pbar = ProgressBar(widgets=widgets, maxval=len(pkgindex), term_width=80).start()
        counter = 0
    for pkgname, archdict in pkgindex.iteritems():
        for arch, pkgobjs in archdict.iteritems():
            if len(pkgobjs) == 0:
                # then we have an empty list. Should never happen, but...
                continue
            if len(pkgobjs) == 1:
                # there's only one version of this package installed
                reduced_list.append(pkgobjs[0])
            else:
                newest = pkgobjs[0]
                for pkg in pkgobjs[1:]:
                    res = latest_pkg(newest, pkg)
                    if res is not None:
                        newest = res
                reduced_list.append(newest)
        if progressbar:
            counter += 1
            pbar.update(counter)
    if verbose:
        print "reduced packagelist to %d entries" % len(reduced_list)
    print
    return reduced_list

def process_system(rhn, systemobj, channelpackagelist, progressbar = False, packagedict = {}, verbose = False):
    """
    Abstracts the system processing parts
    This is run per system and compares its package set to the (reduced) channel package list,
    returning the diffs as a dictionary. Can optionally use a global dictionary object when repeatedly
    run across a number of systems.
    """
    results = packagedict
    installed_pkgs = system.listPackages(RHN, systemobj['id'])
    if check_unknown(installed_pkgs):
        sys_pkgs = get_pkgids(RHN, installed_pkgs, progressbar = progressbar)
        chandiffs = sorted(diff_package_lists(sys_pkgs, chan_pkgs), key=itemgetter('name'))
        if progressbar:
            widgets = ['Finding Errata for packages: ', Counter(), ' packages [', Percentage(), ']', '(', Timer(), ')']
            pbar = ProgressBar(widgets=widgets, maxval=len(chandiffs), term_width=80).start()
        for pkg in chandiffs:
            counter = 1 + chandiffs.index(pkg)
            pkgstr = "%(name)s-%(version)s-%(release)s.%(arch_label)s" % pkg
            errlist = packages.listProvidingErrata(RHN, pkg['id'])
            if len(errlist) > 0:
                errnames = [ x['advisory'] for x in errlist ]
                if results.has_key(pkgstr):
                    for errname in errnames:
                        if errname not in results[pkgstr]:
                            results.append(errname)
                else:
                    results[pkgstr] = errnames
            else:
                if results.has_key('noerrata'):
                    if pkgstr not in results['noerrata']:
                        results['noerrata'].append(pkgstr)
                else:
                    results['noerrata'] = [ pkgstr ]
            if progressbar:
                pbar.update(counter)
    else:
        print "system %s has an outdated version of up2date, please update it" % systemobj['name']
        return None

    return results

# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    # parse the command line
    opts, args = parse_cmdline(sys.argv)
    if opts.quiet:
        verbose = False
        showprogress = False
        debug = False
    else:
        showprogress = True
        verbose = opts.verbose
        debug = opts.debug

    # initialise an RHN Session (the try...except block allows us to interrupt with Ctrl-C)
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # did we require debugging? lots of unpleasant output on failure if we did...
        if debug:
            RHN.enableDebug()

        if opts.profile:
            # then we are only queying one system
            try:
                # lookup the systemid for this system, taking the one that most recently checked in,
                # if there is more than one. (This call always returns a list, or throws an exception)
                systemobj = sorted(system.getId(RHN, opts.profile), key=itemgetter('last_checkin'), reverse = True)[0]
            except:
                print "unable to lookup system record %s. Please check and try again" % opts.profile
                sys.exit(3)

            system_list = [ systemobj ]
            # if we didn't choose a channel to diff against, use the system's base channel:
            if not opts.channel:           
                basechannel = system.getBaseChannel(RHN, systemobj['id'])
                if verbose:
                    print "using software channel '%s' (registered base channel for %s)" %( basechannel, opts.profile)

        if opts.channel:
            # we are querying a whole channel and all its subscribed systems
            basechannel = opts.channel
            if opts.profile:
                # then we should already have a  'systemobj' record
                system_list = [ systemobj ]
            else:
                system_list = channel.listSubscribedSystems(RHN, basechannel)

        # was used for progress reports...
        syscount = len(system_list)

        if not opts.quiet:
            print "Getting a list of packages in channel %s" % basechannel
        chan_pkgs = channel.listAllPackages(RHN, basechannel)
        if not opts.quiet:
            print "reducing package list to latest available versions only"
        reduced_pkgs = reduce_by_arch(chan_pkgs, showprogress, verbose)

        # now process each system
        counter = 1
        global systemdiff
        systemdiff = {}
        for sysrecord in system_list:
            if not opts.quiet:
                print "finding newer packages and associated errata for %s [%d of %d]" % (sysrecord['name'], counter, syscount)
            process_system(RHN, sysrecord, reduced_pkgs, progressbar = showprogress, packagedict = systemdiff)
            print "package diff now has %d entries" %  len(systemdiff)
            counter += 1

        if verbose:
            pprint(systemdiff)

        if opts.output:
            if verbose:
                print "dumping JSON records to output file %s" % opts.output
            if os.path.exists(opts.output):
                res = prompt_confirm('overwrite existing file %s' % opts.output)
            else:
                res = True
            if res:
                utils.dumpJSON(systemdiff, opts.output)


        # DO STUFF with your RHN session and commandline options
    except KeyboardInterrupt:
        print "operation cancelled"
        sys.exit(1)
