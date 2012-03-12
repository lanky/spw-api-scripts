==========================
README for spw-api-scripts
==========================

THis repo contains a load of utility scripts that I wrote (with help in some places) for managing bits and pieces of an RHN satellite.
They all require the *python-rhnapi* module, also available from my github to work.
Some of them also make use of the *python-progressbar* library, borrowed from google code and slightly mangled to work with distutils rather than external python-setuptools, because I had to do a lot of this on RHEL5.

Building RPMs of the scripts
----------------------------
The scripts use python's built-in *distutils*, which means that you should be able to do the following:

1. update setup.cfg to set the appropriate release number (or use ''--release'' on the commandline
2. ''python setup.py bdist_rpm''


The Scripts
-----------
These should all have -h/--help options (totally overengineered in this regard) and (might) do what they sound like.

The scripts (at time of writing) by category

Activation Key Management
~~~~~~~~~~~~~~~~~~~~~~~~~
*   spw-activationkey-clone
    clones an activationkey according to options given
*   spw-activationkey-delete
    deletes the provided list of activationkeys
*   spw-activationkey-export
    exports activation keys to a JSON-format text file
*   spw-activationkey-import
    imports all (or selected) activation keys from a text file 
*   spw-activationkey-list
    lists activation keys and descriptions

Software Channel Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~
*   spw-channel-clone           - clones a software channel.
                                  Allows for recursive cloning, regex substitution, prefix and suffix addition.
*   spw-channel-create          - creates an empty software channel
*   spw-channel-delete          - deletes a software channel. Use with caution.
*   spw-channel-dumppackagelist - dumps out a list of packages for a given channel to a text file. Supports recursion.
*   spw-channel-list            - lists software channels. Supports regex and can display the number of subscribed systems.
*   spw-channel-org-access      - controls / reports on channel sharing across orgs
*   spw-channel-packageaudit    - diffs all subscribed systems package lists against their subscribed channels.
*   spw-channel-packageversions - shows all versions of a given package in specified channels. Supports shell globbing for both channel and package specification.
*   spw-channel-patchsummary    - compares errata in a chosen channel or channel group (from config file) with its original source channel. Can specify

Configuration Channel Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*   spw-configchannel-clone     - clones a configuration channel. Can use regex matching for source and destination. Cloned configuration channels lose revision history, but keep file revision numbers (so essentially a point-in-time snapshot of a given config channel)
*   spw-configchannel-delete    - deletes the specified config channels and all their content. use with care.
*   spw-configchannel-export    - export chosen configuration channel(s) to JSON-format text file
*   spw-configchannel-import    - imports chosen configuration channel(s) from JSON-format text file.
*   spw-configchannel-listfiles - lists content and properties of a given (or all) configuration channels

Kickstart Profile Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*   spw-kickstart-delete        - deletes the chosen kickstart profiles
*   spw-kickstart-export        - exports chosen kickstart profile(s) to JSON text file
*   spw-kickstart-import        - imports kickstart profiles from JSON text file

Software Package Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~
*   spw-package-listerrata      - finds errata for a given package name
*   spw-package-audit           - compares a dump of 'rpm -qa' from a system to a software channel of your choice. Details older/newer packages etc

Errata Management
~~~~~~~~~~~~~~~~~
*   spw-errata-clone            - clones/publishes specified errata

System Management
*   spw-system-list-badarch     - lists systems with packages marked as of 'unknown' arch (finds old rhel4 systems which need updated RHN packages)


Authentication Configuration
----------------------------
I'd create a ~/.rhninfo file if I were you (you'll be prompted for user info anyway, but it simplifies things)
password/login as None essentially means 'prompt'
see templates/rhninfo.template, but it looks like this:::

    [DEFAULT]
    login=None
    password=None

    [your.sat.server]
    login=xxxxxx
    password=None

