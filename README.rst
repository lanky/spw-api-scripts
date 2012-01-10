==========================
README for spw-api-scripts
==========================

THis repo contains a load of utility scripts that I wrote (with help in some places) for managing bits and pieces of an RHN satellite.
They all require the *python-rhnapi* module, also available from my github to work.
Some of them also make use of the *python-progressbar* library, borrowed from google code and slightly mangled to work with distutils rather than external python-setuptools, because I had to do a lot of this on RHEL5.

Building RPMs of the scripts
----------------------------
The scripts use python's built-in *distutils*

The Scripts Themselves
----------------------
These should all have -h/--help options (totally overengineered in this regard) and (might) do what they sound like.

The scripts (at time of writing)
*     spw_audit_packages                  - audits a system's package list against its subscribed channels. Can produce CSV output
                                            (essentially a second implementation of spw_compare_system_to_channel)
*     spw_channel_errata                  - Compares a cloned channel to its source and lists unsynced errata for review
*     spw_channel_org_access              - sets access from 
*     spw_clone_activationkey             - clones an activation key
*     spw_clone_channel                   - clones software channels (recursively if required)
*     spw_clone_configchannel             - clones a configuration channel
*     spw_clone_errata                    - clones/publishes errata by advisory name into a channel of you choice.
*     spw_compare_channel_pkglist         - compares a channel package list to the output of rpm _qa from a given server.
*     spw_compare_system_to_channel       - compares a system to its subscribed software channel (or another)
                                            to list packages in one but not the other.
*     spw_create_channel                  - create a software channel with the chosen options
*     spw_delete_activationkey            - deletes activation key
*     spw_delete_channel                  - deletes software channels
*     spw_delete_configchannel            - deletes config channels
*     spw_delete_kickstart                - deletes a kickstart profile.
*     spw_export_activationkeys           - exports activation keys to JSON
*     spw_export_configchannels           - exports config channels to JSON
*     spw_export_kickstarts               - exports kickstart profiles to JSON
*     spw_import_activationkeys           - imports activation keys from a JSON dump
*     spw_import_configchannels           - imports configuration channels from a JSON dump
*     spw_import_kickstarts               - imports kickstart profiles from a JSON dump
*     spw_list_activationkeys             - lists activation keys and descriptions
*     spw_list_channels                   - channels in a pretty tree format. Accepts regex.
*     spw_list_configfiles                - shows config files from a given config channel, plus properties
*     spw_list_duplicate_systems          - shows duplicate systems (not necessary on 5.4+, but works with 5.3)
*     spw_list_errata_for_package         - searches for errata providing a given package (to assist with cloning)
*     spw_list_unknown_arch_systems       - lists all systems on the satellite with packages marked as of 'unknown' arch.
*     spw_upload_config_file              - does exactly what it says on the tin :)




-----------
  I'd create a ~/.rhninfo file if I were you (you'll be prompted for user info anyway, but it simplifies things)
  password/login as None essentially means 'prompt'
  see templates/rhninfo.template, but it looks like this:

[DEFAULT]
login=None
password=None

[your.sat.server]
login=xxxxxx
password=None

