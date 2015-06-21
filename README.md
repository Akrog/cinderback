This is a script meant to serve as a sample/reference script to facilitate OpenStack's Volume Back up/Restore workflow and to provide workarounds for some of Cinder Backup Service current limitations as explained in these 2 posts:

- [OpenStack's Volume Backup Status][1]
- [Cinder Volume Back Up Automation][2]

Currently this script provides following capabilities:

- Backup/Restore all volumes:
    * From the tenant
    * From all tenants accessible by provided credentials
    * Backups can be hidden to owner tenants if done by admin
    * Admin can easily restore either his backups or tenants and make them visible/invisible to original tenant.
- Backup rotation: Can limit how many automatic backups are kept for each volume
- Can restore by original volume id or by backup id
- Optional preservation of volume's original volume name and description
- Backup in-use volumes through a temporary snapshot and volume creation/destruction
- Export/Import all automatic backups metadata at once into one file

The script has only 2 requirements to run, Python 2.7 and cinderclient v1.1.1 or newer, if an older version is used some of the features will not be available, since they depend on cinderclient support of all-tenants option.

Cinderclient is available from python-cinderclient package or [PyPi's python-cinderclient][3].

Please keep in mind that this is just a sample script, it's not fail proof and therefore is not really production ready.


[1]: http://gorka.eguileor.com/openstacks-volume-backup-status/
[2]: http://gorka.eguileor.com/cinder-volume-back-up-automation
[3]: https://pypi.python.org/pypi/python-cinderclient
