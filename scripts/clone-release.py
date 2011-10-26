#!/usr/bin/env python
# API script to manage your satellite. Requires the python 'rhnapi' module

"""
A preliminary attempt to recreate some of the functionality of the  channel-to-update (aka spacewalk-create-channel) script, using errata cloning/publishing on top of a base no-errata channel.
intended to read a list of packages in the same way that spacewalk-create-channel does.

If this works then we should end up with a channel very like a normal RH satellite channel, but with all appropriate errata available.
"""
__author__ = "Stuart Sears <sjs@redhat.com>"

# standard library imports
import sys
from optparse import OptionParser, OptionGroup
import re
import os

# for package comparison
import rpm

# because some stuff is just a million times faster reading from the DB directly
import cx_Oracle as oracle


####
from progressbar import Counter,Percentage,ProgressBar, Timer, AnimatedMarker, Bar

# custom module imports
import rhnapi
from rhnapi import errata
from rhnapi import packages
from rhnapi import channel

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None
# ---------------------------------------------------------------------------- #
# a partially-tested regex to parse RPM filenames into NVREA dicts
rpmpattern = re.compile(r'(?P<name>[\w\-.+]+)-(?P<version>[\w.]+)-(?P<release>[\w.]+)\.(?P<arch>x86_64|i386|noarch|i686)\.rpm')

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Creates a channel by cloning errata. uses a text file (list of packages) as input."
    usagestr = "%prog [RHNOPTS] -c SOURCE_CHANNEL FILENAME"
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
    rhngrp.add_option("-C", "--cache", action = "store_true", default = False,
        help = "save usernames and password in config file, if missing")
    parser.add_option_group(rhngrp)

    changrp = OptionGroup(parser, "Channel Selection Options")
    changrp.add_option("-c", "--channel", help = "source channel to clone from")
    parser.add_option_group(changrp)

    # script-specific options


    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    opts, args = parser.parse_args(argv)
    # check the args for errors etc...
    if len(args) == 0:
        print "You must provide an input filename"
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args[0]):
        print "'%s' does not appear to exist" % args[0]
        sys.exit(2)

    if not opts.channel:
        print "You must provide a source channel to clone from"
        sys.exit(3)

    # finally...
    return opts, args
    
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

def parse_rpmnames(inputfile):
    """
    reads in a text file,  line-by-line.
    returns a list of dict, one per parsed package name
    fd      - file descriptor (e.g. open(filename))
    """
    output = []
    rejects = []
    counter = 0
    for pkgname in open(inputfile):
        match = rpmpattern.match(pkgname)
        if match:
            output.append(match.groupdict())
        else:
            rejects.append(pkgname)
        counter += 1

    return output, rejects

def dictRowFactory(cursor, labels = None):
    """
    Converts a row retrieved from a DB query into a dictionary

    parameters:
    cursor          - a cx_Oracle.cursor instance
    labels(list)    - a list, in order, of the key names to use.
                      defaults to the fields requested in the query
                      which can be VERY weird if doing regexp_replace or other trickery.
    """
    if labels is None:
        labels = x.lower() for x in cursor.description

    def createRow(*args):
        """
        generates a dict from the labels list and the entries in a row tuple
        """
        return dict(zip(labels, args))

    return createRow


    

def get_errata_packages():
    """
    uses a DB connection and a SQL query to get package ID, advisory names and filenames
    for all packages in a satellite provided by errata

    parameters:
    packagelist             -  a list of package filenames (e.g. from the spacewalk-create-channel data lists)
    """
    db = oracle.Connection("rhnsat/rhnsat@rhnsat")
    curs = db.cursor()
    
#    stmt = """select p.package_id, e.advisory_name, regexp_.replace(r.path, '.*/([^/]+$), '\\1') from 
#            rhnpackage r, rhnerrata e, rhnerratafile f, rhnerratafilepackage p where
#            f.errata_id=e.id and p.errata_file_id=f.id and r.id=p.package_id
#            """
    stmt = "select r.id, e.advisory_name, regexp_replace(r.path, '.*/([^/]+$)', '\\1') from rhnpackage r, rhnerrata e, rhnerratafile f, rhnerratafilepackage p where f.errata_id=e.id and p.errata_file_id=f.id and r.id=p.package_id"
    curs.execute(stmt)
    curs.rowfactory = dictRowFactory(cur, labels = [ 'id', 'errata', 'filename'])

    output = curs.fetchall()

    return output

def get_nvreas():
    """
    uses the DB to fetch a list of dicts representing RPM packages with (epoch, version, release) tuples
    """
    def pkgFactory(cursor):
        """
        specifc to the get_nvreas method, so inside it.
        """
        def createRow(*args):
            return { 'id' : args[0], 'name' : args[1], 'evr' : ( args[2], args[3], args[4] ) }
    db = Oracle.Connection("rhnsate/rhnsat@rhnsat")



def get_nonerrata_packages(rhn, chan, erratapkgs):
    """
    get a list of package IDs and names that are not provided by an erratum.
    These should ideally be the same as GA for that channel.

    parameters
    rhn                 - an authenticated RHN session
    chan(str)           - channel label
    erratapkgs(dict)    - dict provided by get_errata_packages
    """
    pkglist = channel.listAllPackages(rhn, chan)

    pkgids = set([ x['id'] for x in pkglist ])
    errids = ([ v['id'] for k, v  in erratapkgs.iteritems() ])

    pkgdiff = pkgids.difference(errids)

    return list(pkgdiff)
        
        

        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    # initialise an RHN Session
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache, debug=opts.debug)
        if RHN.key:
            # setup logging (off by default)
            RHN.addLogger("clone-release", "/tmp/clone-release.log")
            # log the session start
            RHN.logger.info("Logged into satellite %s as %s" %(RHN.hostname, RHN.login))

            print "listing of packages in channel %s" % opts.channel

            channelpkgs = channel.listAllPackages(RHN, opts.channel)

            # print "listing errata in channel %s" % opts.channel

            # channelerr  = channel.listErrata(RHN, opts.channel)

            print "aligning packages in channel %s with providing errata" % opts.channel

            errata_map = get_errata_packages()

            counter = 0
            widgets = [ 'Indexed ', Counter(), ' Packages | ', Timer() ]
            pbar = ProgressBar(widgets = widgets, maxval = len(channelpkgs) ).start()
            for p in channelpkgs:
                p['errata'] = [ e['advisory'] for e in packages.listProvidingErrata(RHN, p['id']) ]
                counter += 1
                pbar.update(counter)

            pkgs, rejects = parse_rpmnames(args[0])

            # fetch the matching package entries out of the channel packages list
            # this is to be certain we include the 


            
                


        # well, if no RHN key, we failed to login. For some reason this does not raise an xmlrpclib.Fault
        else:
            print "unable to login to satellite server %s as %s" %(opts.server, opts.login)
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)


    
    
    
