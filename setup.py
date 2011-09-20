#!/usr/bin/env python
# -*- coding: utf-8 -*-
# setup script for packaging the rhnapi module
import sys
# print "currently nonfunctional."
# sys.exit(0)

from distutils.core import setup
setup(name = 'satellite-api-utils',
      version = '5.4',
      description = 'RHN Satellite XMLRPC API scripts and utilities',
      author = 'Stuart Sears',
      author_email = 'sjs@redhat.com',
      scripts = [
          "scripts/audit-packages.py",
          "scripts/channel-errata.py",
          "scripts/channel-org-access.py",
          "scripts/clone-activationkey.py",
          "scripts/clone-channel.py",
          "scripts/clone-configchannel.py",
          "scripts/clone-errata.py",
          "scripts/compare-channel-pkglist.py",
          "scripts/compare-system-to-channel.py",
          "scripts/create-channel.py",
          "scripts/delete-activationkey.py",
          "scripts/delete-channel.py",
          "scripts/delete-configchannel.py",
          "scripts/delete-kickstart.py",
          "scripts/export-activationkeys.py",
          "scripts/export-configchannels.py",
          "scripts/export-kickstarts.py",
          "scripts/import-activationkeys.py",
          "scripts/import-configchannels.py",
          "scripts/import-kickstarts.py",
          "scripts/list-activationkeys.py",
          "scripts/list-channels.py",
          "scripts/list-configfiles.py",
          "scripts/list-duplicate-systems.py",
          "scripts/list-errata-for-package.py",
          "scripts/list-unknown-arch-systems.py",
          "scripts/upload-config-file.py",
      ],
      )



