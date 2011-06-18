#!/usr/bin/env python
# -*- coding: utf-8 -*-
# setup script for packaging the rhnapi module
import sys
print "currently nonfunctional."
sys.exit(0)

from distutils.core import setup
setup(name = 'satellite-api-utils',
      version = '1.0',
      description = 'RHN Satellite XMLRPC API scripts and utilities',
      author = 'Stuart Sears',
      author_email = 'sjs@redhat.com',
      packages = [ 'scripts' ],
      )


