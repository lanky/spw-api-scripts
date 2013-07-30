#!/usr/bin/env python
# -*- coding: utf-8 -*-
# setup script for packaging the rhnapi module
import sys
import os
import glob
# print "currently nonfunctional."
# sys.exit(0)

from distutils.core import setup
setup(name = 'spw-api-scripts',
      version = '5.4.1',
      description = 'RHN Satellite / Spacewalk XMLRPC API scripts and utilities. Require python-rhnapi and python-progressbar.',
      long_description = 'XMLRPC API scripts for RHN Satellite  / Spacewalk automation. Written using the python-rhnapi module. All scripts have commandline help features. Some may be a little buggy.',
      author = 'Stuart Sears',
      author_email = 'stuart@sjsears.com',
      license = 'GPL v2+',
      download_url = 'https://github.com/lanky/spw-api-scripts',
      scripts = glob.glob(os.path.join('scripts', 'spw-*')),
      )






































