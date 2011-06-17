#!/usr/bin/env python
# -*- coding: utf-8 -*-
# a script to dump a kickstart profile to JSON
__doc__="""
export-kickstarts.py
A script to extract information about an RHN satellite kickstart profile and export it to JSON.
This includes the following:
* kickstart options
  - package profiles
  - locale
  - SELinux settings
  - 
* activation keys
  - configuration channels 
  - system groups

"""
# standard library imports
import sys
from optparse import OptionParser, OptionGroup
# simplejson becomes plain 'json' in future python releases

# custom module imports. Make sure they're on your PYTHONPATH :)
import rhnapi
from rhnapi import kickstart
from rhnapi import activationkey
# this needs editing to add the ID->name functionality:
from rhnapi import systemgroup
from rhnapi import utils

RHNHOST = 'localhost'
RHNCONFIG = '~/.rhninfo'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None


# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Dump a kickstart profile (or all profiles) to a JSON-format text file"
    usagestr = "%prog [RHNOPTS] [KICKSTART-OPTS]"
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
    ksgrp = OptionGroup(parser, "Kickstart-specific options")
    ksgrp.add_option("--list", action="store_true", default=False, help="List kickstart labels and exit")
    ksgrp.add_option("-a", "--all", action="store_true", default=False, help="dump data for ALL kickstart profiles")
    ksgrp.add_option("-k", "--kickstart", help="kickstart label. Can also take a comma-separated list. No spaces.")
    ksgrp.add_option("-f", "--file", help="filename to dump kickstart information to [KICKSTARTLABEL.json]")
    ksgrp.add_option("-n", "--not-really", action="store_true", default=False, help="DRY RUN. Pretty print data to stdout")
    parser.add_option_group(ksgrp)

    opts, args = parser.parse_args()

    # check the args for errors etc...
    if not opts.list and not opts.kickstart and not opts.all:
        print "You must provide either a kickstart label (or --all) or the --list option"
        parser.print_help()
        sys.exit(1)

    # finally...
    return opts, args

# --------------------------------------------------------------------------------- #

def get_ks_details(rhn, ksobject, verbose = False):
    """
    suck all the details out of your satellite for a given kickstart label
    and merge them into a single dict structure.
    For some reason this takes about 43 different methods

    returns:
    dict (a kickstart structure)

    params:
    rhn:                    an authenticated rhnapi.rhnSession
    ksobject                a dict structure containing base kickstart info
    verbose                 whether to make more noise
    """
    kslabel = ksobject.get('label')
    ksobject['child_channels']        = kickstart.getChildChannels(rhn, kslabel)
    ksobject['advanced_opts']         = kickstart.getAdvancedOptions(rhn, kslabel)
    ksobject['software_list']         = kickstart.getSoftwareList(rhn, kslabel)
    ksobject['custom_opts']           = kickstart.getCustomOptions(rhn, kslabel)
    # technically included in the base kickstart info:
    ksobject['ks_tree']               = kickstart.getKickstartTree(rhn, kslabel)
    # list all the pre and post scripts
    ksobject['script_list']           = kickstart.listScripts(rhn, kslabel)
    ksobject['ip_ranges']             = kickstart.listIpRanges(rhn, kslabel)
    # custom kickstart variables
    ksobject['variable_list']         = kickstart.getVariables(rhn, kslabel)
    
    # activation keys are complicated and we need more information than the defaults
    # in case they must be recreated on import:
    ksobject['activation_keys']       = kickstart.getActivationKeys(rhn, kslabel)
    for akey in ksobject['activation_keys']:
        akey['config_channels'] = activationkey.listConfigChannels(rhn, akey['key'])
        akey['config_deploy'] = activationkey.checkConfigDeployment(rhn, akey['key'])
        if len(akey['server_group_ids']) != 0:
            akey['server_groups'] = get_group_details(rhn, akey['server_group_ids'])
        
    ksobject['partitioning_scheme']   = kickstart.getPartitioningScheme(rhn, kslabel)
    ksobject['reg_type']              = kickstart.getRegistrationType(rhn, kslabel)
    # technically this is unnecessary as it is part of the 'advanced options' in kickstart:
    ksobject['selinux_mode']          = kickstart.getSELinux(rhn, kslabel)
    ksobject['file_preservations']    = kickstart.listFilePreservations(rhn, kslabel)
    ksobject['gpg_ssl_keys']          = kickstart.listCryptoKeys(rhn, kslabel)
    ksobject['config_mgmt']           = kickstart.checkConfigManagement(rhn, kslabel)
    ksobject['remote_cmds']           = kickstart.checkRemoteCommands(rhn, kslabel)
    # so, there's a setLogging, but not a getLogging equivalent. huh?
    # ksobject['logging']               = kickstart.getLogging(rhn, kslabel)
    
    # group ids will not be the same on all servers, so we need their names too:
    
    return ksobject
        
# --------------------------------------------------------------------------------- #

def get_group_details(rhn, groupids, verbose = False):
    """
    Call out to rhnapi.systemgroup to get group details for each group in groupids
    We need group names, ideally as IDs could differ from satellite to satellite.
    To avoid too much code, we simply call the getDetails method.
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

def dump_to_file(filename, kickstart_info, verbose = False):
    """
    simply attempts to dump the kickstart data to a given file on disk.

    """
    if verbose:
        print "dumping kickstart data to %s" % filename
    outdata = simplejson.dumps(kickstart_info)
    try:
        outfile = open(filename, 'wb')
        outfile.write(outdata)
        outfile.close()
    except OSError:
        print "could not open output file for writing. Check permissions?"
        return False
        
# --------------------------------------------------------------------------------- #

if __name__ == '__main__':
    
    # parse the command line options and arguments:
    opts, args = parse_cmdline(sys.argv)
    try:
        # initialiase an RHN Session
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        if opts.debug:
            RHN.enableDebug()
        # collect some information from the satellite for later use:
        # a list of all existing kickstart profiles:
        all_kickstarts = kickstart.listKickstarts(RHN)
        # just their labels for 'does this exist?' and '--list' options
        ks_labels = [ x.get('label') for x in all_kickstarts ]
        # an empty list, to which we append each kickstart we are extracting
        kickstart_details = []
        if opts.list:
            print '\n'.join( [ x['label'] for  x in all_kickstarts ])
            sys.exit(0)
        # DO STUFF
        if opts.kickstart:
            for kslabel in opts.kickstart.split(','):
                if kslabel in ks_labels:
                    ksobject = [ x for x in all_kickstarts if x.get('label') == kslabel ][0]
                    kickstart_details.append(get_ks_details(RHN, ksobject, opts.verbose))
                else:
                    print "cannot locate kickstart label %s, does it really exist?" % kslabel
                    print "skipping for the time being"
                    continue

        # are we dumping all kickstart profiles?
        if opts.all:
            if opts.verbose:
                print "processing all kickstarts. This could take a while"
            for ksobject in all_kickstarts:
                print "processing kickstart %s" % ksobject['label']
                kickstart_details.append(get_ks_details(RHN, ksobject, opts.verbose))

        # is this just a test to show what would be done?
        if opts.not_really:
            pprint(kickstart_details)
            sys.exit(0)

        # did we specify an output file?
        if opts.file:
            outputfile = opts.file
        else:
            if opts.all:
                outputfile = 'all-kickstarts.json'
            elif opts.kickstart :
                outputfile = '%s.json' % '_'.join(opts.kickstart.split(','))

        # did we successfully extract at least one kickstart?
        if len(kickstart_details)  != 0:
            # dump_to_file(outputfile, kickstart_details, opts.verbose)
            utils.dumpJSON(kickstart_details, outputfile, verbose=opts.verbose)
        else:
            print "None of the chosen kickstart labels could be successfully dumped"
        
    # handle CTRL-C in the middle of the process
    except KeyboardInterrupt:
        print "operation cancelled\n"
        sys.exit(1)


    
    
    
