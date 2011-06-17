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

# custom module imports
import rhnapi
from rhnapi import configchannel

# configuration variables. Probably okay, actually.
RHNCONFIG = '~/.rhninfo'
RHNHOST = 'localhost'
# put these in your configfile, dammit;
RHNUSER = None
RHNPASS = None
# Column separator
fieldsep = " | "
# shorter names for field for prettier output
mapped_fields = { 'permissions_mode' : 'perms',
                  'selinux_ctx' : 'context',
                }
                    

# --------------------------------------------------------------------------------- #
def parse_cmdline(argv):
    """
    process the commandline :)
    """
    preamble = "Lists contents of the chosen configuration channels in a tabular format"
    usagestr = "%prog [RHNOPTS] [-a|-c] [-f]"
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
    cfggrp = OptionGroup(parser, "Configuration Channel Options")
    cfggrp.add_option("-a", "--all", action = "store_true", default  = False,
        help = "list all channels and their content files")
    cfggrp.add_option("-c", "--channel", help = "list only the specified channel(s). Comma-separated list if more than one.")
    cfggrp.add_option("-f","--fields", help = "comma-separated list of fields to display per file. choose from: perms,owner,group,context,type")
    parser.add_option_group(cfggrp)


    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    opts, args = parser.parse_args(argv)
    # check the args for errors etc...
    if opts.all and opts.channel:
        print "Cannot specify both -a and -c at the same time"
        parser.print_help()
        sys.exit(1)

    # finally...
    return opts, args
        
# --------------------------------------------------------------------------------- #

def print_data(data):
    """
    pretty-prints the given channel data
    """
    # calculate maximum field widths for pretty output:
    fwidths = {}
    for field in data.get('headers'):
        hlen = len(mapped_fields.get(field, field))
        fwidths[field] = max(get_maxwidth(data['files'], field), hlen)

    # adjust the titlebar fields
    # to avoid in-place mullarkey:
    titlebar = []
    for h in data.get('headers'):
        x = mapped_fields.get(h, h)
        titlebar.append("%s" % x.upper().ljust(fwidths[h]))

    # and the printing part:
    tbar = fieldsep.join(titlebar)

    print
    print "Channel: %(label)s (%(name)s)" % data
    print tbar
    print "-" * len(tbar)
    for f in data.get('files'):
        #for h in data.get('headers'):
        #    print "%s%s" % (f[h].ljust(fwidths[h]), fieldsep),
        print fieldsep.join([ f[h].ljust(fwidths[h]) for h in data.get('headers')])

# --------------------------------------------------------------------------------- #

def get_maxwidth(filelist, field):
    """
    Returns the length of the longest value of a given key from a
    list of dict
    """
    # handle shorter names in mapped_fields (for easier printing)
    fname = mapped_fields.get(field, field)
    return max([ len(x.get(field)) for x in filelist] + [len(fname)])
    




# --------------------------------------------------------------------------------- #
if __name__ == '__main__':
    
    opts, args = parse_cmdline(sys.argv[1:])
    # initialise an RHN Session
    # safety mechanism until the script actually works:
    try:
        RHN = rhnapi.rhnSession(opts.server, opts.login, opts.password, config=opts.config, cache_creds=opts.cache)
        # handle debugging requests
        if opts.debug:
            RHN.enableDebug()
        if opts.all:
            mychannels = configchannel.listGlobals(RHN)
        else:
            mychannels = configchannel.lookupChannelInfo(RHN, opts.channel.split(','))

        if opts.fields:
            headers = []
            for field in opts.fields.split(','):
                if field == 'perms':
                    headers.append('permissions_mode')
                elif field == 'context':
                    headers.append('selinux_ctx')
                else:
                    headers.append(field)
        else:
            headers = [ 'path', 'type', 'owner', 'group', 'permissions_mode', 'selinux_ctx' ]

        for chan in mychannels:
            chandata = { 'name' : chan.get('name'),
                         'label' : chan.get('label'),
                         'headers' : headers,
                         'files' : [],
                         }
            chanfiles = [ f['path'] for f in configchannel.listFiles(RHN, chan['label'])]
            for f in configchannel.lookupFileInfo(RHN, chan['label'], chanfiles):
                fileinfo = {}
                for h in chandata['headers']:
                    fileinfo[h] = f.get(h, '-')

                chandata['files'].append(fileinfo)
            print_data(chandata)
        # quick test
        # print chandata


            

        # DO STUFF with your RHN session and commandline options
    except KeyboardInterrupt:
        print "Operation cancelled by keystroke."
        sys.exit(1)


    
    
    
