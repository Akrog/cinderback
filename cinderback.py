#!/bin/env python

# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import base64
from collections import defaultdict
from distutils.version import LooseVersion
from datetime import datetime
import json
import logging
from operator import attrgetter
import os
import sys
import time

from cinderclient import client
from cinderclient import v2
from cinderclient import __version__ as cinder_version


__version__ = '0.1'


# Available script actions
BACKUP = 'backup'
RESTORE = 'restore'
LIST = 'list'
EXPORT = 'export'
IMPORT = 'import'

_LI = _LW = _LE = _LC = _LX = None
DEFAULT_LOG_LEVEL = logging.INFO


def get_arg_parser():
    """Create parser with script options."""

    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            sys.stderr.write('\nerror: %s\n' % message)
            sys.exit(2)

    general_description = (
        "Cinder auto backup management tool\n\n"
        "This is a helper for OpenStack's Cinder backup functionality to help "
        "create and restore automatic backups, with rotation, as well as "
        "export and import backup metadata.\n\n"
        "Metadata for backup volumes is stored in the DB and if this is lost, "
        "Cinder won't be able to restore volumes from backups. So it is "
        "recommended to always export your backup metadata and keep it "
        "safe.\n\n"
        "Currently Cinder can only backup available volumes, so for in-use "
        "volumes this helper will create a temporary snapshot of the volume, "
        "create a temporary volume from that snapshot and create the backup "
        "from that snapshot. This means that if we look in Cinder backup the "
        "volume id will not match the originator. This helper will show "
        "original volume id on list. Once Cinder supports backup from snapshot"
        " the volume creation step will be removed.\n\n"
        "This tool does not support incremental backups since its behavior is "
        "not consistent between all drivers at this moment.\n\n"
        "Cinder backup by default doesn't restore volume name and description,"
        " but this helper does.")

    general_epilog = (
        "Use {action} -h to see specific action help\n\n"
        "*Basic usage:*\n"
        "Create backups for all our volumes using credentials from environment"
        " and keep only the previous backup (delete older ones):\n"
        "\tcinderback.py backup --keep-only 2\n"
        "Restore latests backups for all our volumes using credentials from "
        "environment:\n"
        "\tcinderback.py restore\n"
        "List existing automatic backups:\n"
        "\tcinderback.py list\n"
        "\n*Advanced usage:*\n"
        "As administrator create backups of all tenants volumes, export "
        "metadata and hide backups from tenants:\n"
        "\tcinderback.py --all-tenants backup --forget-tenants "
        "--export-metadata ./backup.metadata\n"
        "As administrator import metadata and restore all backups created by "
        "us (if we created volumes for other tenants they will also be "
        "restored) to their original ids (volumes with those ids must "
        "exist):\n"
        "\tcinderback.py restore --restore-id --import-metadata "
        "./backup.metadata\n"
        "As administrator import newest backups for every volume (created by "
        "us or by tenants):\n"
        "\tcinderback.py --all-tenants restore\n"
        "Restore only 1 specific automatic backup using the backup id (used "
        "for non last backups):\n"
        "\tcinderback.py restore --backup_id $backup_uuid\n"
        "Restore only latest automatic backup for specific volume:\n"
        "\tcinderback.py restore --volume-id $volume_id\n"
        "List existing backups from all tenants:\n"
        "\tcinderback.py --all-tenants list\n")

    parser = MyParser(description=general_description,
                      epilog=general_epilog, version=__version__,
                      add_help=True,
                      formatter_class=argparse.RawTextHelpFormatter)

    # Common arguments to all actions
    parser.add_argument('-a', '--all-tenants', dest='all_tenants',
                        action='store_true', default=False,
                        help='include volumes/backups from all tenants, needs '
                        'cinderclient v1.1.1 (default only from supplied '
                        'tenant)')
    parser.add_argument('--os-username', metavar='<auth-user-name>',
                        dest='username',
                        default=os.environ.get('OS_USERNAME', ''),
                        help='OpenStack user name. Default=env[OS_USERNAME]')
    parser.add_argument('--os-password', metavar='<auth-password>',
                        dest='password',
                        default=os.environ.get('OS_PASSWORD', ''),
                        help='Password for OpenStack user. '
                        'Default=env[OS_PASSWORD]')
    parser.add_argument('--os-tenant-name', metavar='<auth-tenant-name>',
                        dest='tenant_name',
                        default=os.environ.get('OS_TENANT_NAME', ''),
                        help='Tenant name. Default=env[OS_TENANT_NAME]')
    parser.add_argument('--os-auth-url', metavar='<auth-url>', dest='auth_url',
                        default=os.environ.get('OS_AUTH_URL', ''),
                        help='URL for the authentication service. '
                             'Default=env[OS_AUTH_URL]')
    parser.add_argument('-q', '--quiet', dest='quiet',
                        default=False, action='store_true',
                        help='No output except warnings or errors')

    # Subparser for available actions
    subparsers = parser.add_subparsers(title='actions', dest='action',
                                       help='action to perform')

    # Metadata export action
    parser_export = subparsers.add_parser(EXPORT,
                                          help='export backups metadata')
    parser_export.add_argument('filename', metavar='<FILENAME>',
                               help='file to export to')

    # Metadata import action
    parser_import = subparsers.add_parser(IMPORT,
                                          help='import backups metadata')
    parser_import.add_argument('filename',  metavar='<FILENAME>',
                               help='file to import from')

    # Backups list action
    subparsers.add_parser(LIST, help='list available automatic backups')

    # Keep tenants argument is common to backup and restore
    forget_tenants = dict(dest='keep_tenants', action='store_false',
                          default=True, help="don't make backups available to "
                          "original tenant (default available)")

    # Timeout argument is common to backup and restore
    timeout = dict(dest='max_secs_gbi', type=int, default=300,
                   help='maximum expected time in seconds to transfer each '
                   'GB, for timeout purposes. Backup/Restored Volume  will be '
                   'deleted if it timeouts (default 5 minutes)')

    # Backup action
    parser_backup = subparsers.add_parser(BACKUP, help='do backups')
    parser_backup.add_argument('--export-metadata', dest='filename',
                               default=None,  metavar='<FILENAME>',
                               help='export all auto backup metadata to file')
    parser_backup.add_argument('--forget-tenants', **forget_tenants)
    parser_backup.add_argument('--timeout-gb', **timeout)
    parser_backup.add_argument('--keep-only', dest='keep_only', default=0,
                               metavar='<#>',
                               type=int, help='backup rotation, how many '
                                              'automatic backups to keep, '
                                              'oldest ones will be deleted '
                                              '(default keep all)')

    # Restore action
    parser_restore = subparsers.add_parser(RESTORE, help='restore backups',
                                           epilog='Restore last backup')

    parser_restore.add_argument('--timeout-gb', **timeout)
    parser_restore.add_argument('--forget-tenants', **forget_tenants)
    parser_restore.add_argument('--restore-id',
                                dest='restore_id',
                                default=False, action='store_true',
                                help='restore backup to the original '
                                     'volume id, it must exist in cinder '
                                     '(default create new id)')
    parser_restore.add_argument('--forget-data',
                                dest='restore_data',
                                default=True, action='store_false',
                                help="don't restore volume's name and "
                                     "description (default restore)")
    parser_restore.add_argument('--import-metadata', dest='filename',
                                default=None, metavar='<FILENAME>',
                                help='import auto backup metadata from file')

    parser_restore_id = parser_restore.add_mutually_exclusive_group()
    parser_restore_id.add_argument('--volume-id',
                                   dest='volume_id',
                                   default=None,
                                   help='specific volume to restore')
    parser_restore_id.add_argument('--backup-id',
                                   dest='backup_id',
                                   default=None,
                                   help='specific backup to restore')
    return parser


def create_logger(quiet=False):
    global _LI, _LW, _LE, _LC, _LX

    logger = logging.getLogger(__name__)

    logger.setLevel(logging.WARNING if quiet else DEFAULT_LOG_LEVEL)

    # create console handler and set level
    ch = logging.StreamHandler()
    ch.setLevel(DEFAULT_LOG_LEVEL)

    # create formatter for ch
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    _LI = logger.info
    _LW = logger.warning
    _LE = logger.error
    _LC = logger.critical
    _LX = logger.exception

    return logger


class BackupInfo(object):
    """Representation of volume information to store in backup description."""

    @staticmethod
    def _from_b64_json(data):
        """Convert from base 64 json data to Python objects."""
        return json.loads(base64.b64decode(data))

    def __init__(self, data):
        """Accept string, backup or volume classes."""
        # For strings we assume it's the __repr__ value
        if isinstance(data, str):
            self.__dict__ = self._from_b64_json(data)

        # If it's a backup we extract information from the description
        elif isinstance(data, v2.volume_backups.VolumeBackup):
            self.__dict__ = self._from_b64_json(data.description)

        # If it's a volume we store relevant volume information.
        # At this point in time it's only id, tenant, name and description.
        elif isinstance(data, v2.volumes.Volume):
            self.id = data.id
            self.owner_tenant_id = getattr(data,
                                           'os-vol-tenant-attr:tenant_id')
            self.name = data.name
            self.description = data.description

        # We don't know how to treat additional types
        else:
            raise ValueError('data argument is of unknown class %s',
                             type(data))

    def __repr__(self):
        """Base 64 encodejson representation of instance."""
        return base64.b64encode(json.dumps(self.__dict__))


class BackupServiceException(Exception):
    def __init__(self, what, *args, **kwargs):
        super(BackupServiceException, self).__init__(*args, **kwargs)
        self.what = what

    def __str__(self):
        return u'%s: %s' % (self.__class__.__name__, self.what)


class UnexpectedStatus(BackupServiceException):
    def __init__(self, what, intermediate='', final='', *args, **kwargs):
        super(UnexpectedStatus, self).__init__(what, *args, **kwargs)
        self.intermediate = intermediate
        self.final = final

    def __str__(self):
        if self.intermediate or self.final:
            steps = (' [intermediate: %s, final: %s]' %
                     (self.intermediate, self.final))
        else:
            steps = ''
        return (u'%s: Status is %s%s' %
                (self.__class__.__name__, self.what.status, steps))


class TimeoutError(BackupServiceException):
    pass


class BackupIsDown(BackupServiceException):
    pass


class BackupService(object):
    """Backup creation and restoration class."""

    # Poll interval in seconds when creating or destroying resources.
    default_poll_deplay = 10
    WANT_V = '1.1.1'
    HAS_SEARCH_OPTS = LooseVersion(cinder_version) >= LooseVersion(WANT_V)

    def __init__(self, username, api_key, project_id, auth_url,
                 poll_delay=None, name_prefix='auto_backup_',
                 max_secs_gbi=None):
        super(BackupService, self).__init__()
        self.username = username
        self.api_key = api_key
        self.project_id = project_id
        self.auth_url = auth_url
        self.poll_delay = poll_delay or self.default_poll_deplay
        self.name_prefix = name_prefix

        # Some functionality requires API version 2
        self.client = client.Client(version=2,
                                    username=username,
                                    api_key=api_key,
                                    project_id=project_id,
                                    auth_url=auth_url)

        self.status_msg = ''
        self.max_secs_gbi = max_secs_gbi or 300

        if not self.HAS_SEARCH_OPTS:
            _LW('--all-tenants disabled, need cinderclient v%s', self.WANT_V)

    @property
    def backup_status(self):
        """On error this may have additional information."""
        return self.status_msg

    @property
    def is_up(self):
        """Check whether backup service is up and running or not.
        If we are not allowed to check it we assume it's always up."""
        # Get services list
        try:
            services = self.client.services.list()

        # If policy doesn't allow us to check we'll have to assume it's there
        except client.exceptions.Forbidden:
            return True

        # Search for cinder backup service
        for service in services:
            if service.binary == 'cinder-backup':
                # Must be up
                if service.state != 'up':
                    self.status_msg = service.state
                    return False
                # And enabled
                if service.status != 'enabled':
                    self.status_msg = service.status
                    if service.disabled_reason:
                        self.status_msg += ' (%s)' % service.disabled_reason
                    return False
                return True

        # If we can't even find it in services list it's not loaded
        self.status_msg = "Not loaded"
        return False

    def _list_arguments(self, all_tenants):
        if self.HAS_SEARCH_OPTS:
            return {'search_opts': {'all_tenants': all_tenants}}

        return {}

    def backup_all(self, all_tenants=True, keep_tenant=True, keep_only=0):
        """Creates backup for all visible volumes.

        :all_tenants: Backup volumes for all tenants, not only ourselves.
        :param keep_tenant: If we want owners to see automatic backups of their
                            volumes. Only relevant when using all_tenants=True
        :param keep_only: Amount of backups to keep including the new one.
                          Older ones will be deleted.
        :return: ([successful_backup_object], [failed_volume_object])

        """
        backups = []
        failed = []

        # Get visible volumes
        volumes = self.client.volumes.list(**self._list_arguments(all_tenants))

        # Get existing backups
        existing_backups = self.existing_backups(all_tenants=all_tenants)

        _LI('Starting Volumes Backup')
        for vol in volumes:
            _LI('Processing %dGB from volume %s (id: %s)', vol.size, vol.name,
                vol.id)
            backup_name = self.name_prefix + vol.id

            # See owner tenant and check if it's us
            owner_tenant_id = getattr(vol, 'os-vol-tenant-attr:tenant_id')

            # If we want to keep the tenant, get the right client
            tenant_client = self.get_client(owner_tenant_id, keep_tenant)

            # Do the backup
            try:
                backup = self.backup_volume(vol, name=backup_name,
                                            client=tenant_client)
            except BackupIsDown:
                raise
            except TimeoutError:
                _LE('Timeout on backup')
                failed.append(vol)
                backup = None
            except UnexpectedStatus:
                failed.append(vol)
            except client.exceptions.OverLimit as exc:
                _LE('Error while doing backup %s', exc)
                failed.append(vol)
                break
            except Exception:
                _LX('Exception while doing backup')
                failed.append(vol)
                backup = None

            # On success
            else:
                backups.append(backup)
                existing_backups[vol.id].append(backup)
                # If we limit the number of backups and we have too many
                # backups for this volume
                if (keep_only and len(existing_backups.get(vol.id, tuple())) >
                        keep_only):
                    remove = len(existing_backups[vol.id]) - keep_only
                    # We may have to remove multiple backups and we remove the
                    # oldest ones, which are the first on the list.
                    for __ in xrange(remove):
                        back = existing_backups[vol.id].pop(0)
                        _LI('Removing old backup %s from %s', back.id,
                            back.created_at_dt)
                        self._delete_resource(back, need_up=True)
            _LI('Backup completed')
        _LI('Finished with backups')
        return (backups, failed)

    def _wait_for(self, resource, allowed_states, expected_states=None,
                  need_up=False):
        """Waits for a resource to come to a specific state.

        :param resource: Resource we want to wait for
        :param allowed_states: iterator with allowed intermediary states
        :param expected_states: states we expect to have at the end, if None
                                is supplied then anything is good.
        :param need_up: If wee need backup service to be up and running
        :return: The most updated resource
        """
        deadline = time.time() + (self.max_secs_gbi * resource.size)
        while resource.status in allowed_states:
            time.sleep(self.poll_delay)
            if need_up and not self.is_up:
                raise BackupIsDown(what=resource)
            if deadline <= time.time():
                raise TimeoutError(what=resource)
            resource = resource.manager.get(resource.id)

        if expected_states and resource.status not in expected_states:
            raise UnexpectedStatus(what=resource, intermediate=allowed_states,
                                   final=expected_states)

        return resource

    def _delete_resource(self, resource, wait=True, need_up=False):
        # Snapshots and volumes, may be used with backups if need_up=True
        if not resource:
            return

        try:
            resource.delete()
            if wait:
                self._wait_for(resource, ('deleting',), need_up=need_up)

        # If it doesn't exist we consider it "deleted"
        except client.exceptions.NotFound:
            pass

    def _create_and_wait(self, msg, module, arguments, resources=tuple()):
        """Creates a resource and waits for completion, with optional cleanup
        on error.

        :param msg: Message to display on start
        :param module: Module to create resource from
        :param arguments: Arguments for resource creation
        :param resources: Allocated resources that must be cleaned up on error
        :return: Created resource
        """
        def _cleanup(new_resource):
            self._delete_resource(new_resource)
            for res in resources:
                self._delete_resource(res)

        _LI(msg)
        result = None
        try:
            result = module.create(**arguments)
            result = self._wait_for(result, ('creating',), 'available', True)
        except:
            _cleanup(result)
            raise

        return result

    def backup_volume(self, volume, name=None, client=None):
        """Backup a volume using a volume object or it's id.

        :param volume: Volume object or volume id as a string.
        :param name: Name for the backup
        :param client: If we want ot use a specific client instead of this
                       instance's client. Useful when creating backups for
                       other tenants.
        :return: Backup object
        """
        if isinstance(volume, str):
            # TODO: This could fail
            volume = self.client.volumes.get(volume)

        # Use given client or instance's client
        client = client or self.client
        name = name or self.name_prefix + volume.id

        # Use encoded original volume info as description
        description = BackupInfo(volume)

        if volume.status == 'in-use':
            _LI('Volume online so this is a multi-step process')

            # Force snapshot since volume it's in-use
            snapshot = self._create_and_wait(
                'Creating snapshot', client.volume_snapshots,
                arguments=dict(
                    volume_id=volume.id, force=True, name='tmp ' + name,
                    description='Temporary snapshot for backup',
                    metadata=volume.metadata))

            # Create temporary volume from snapshot
            tmp_vol = self._create_and_wait(
                'Creating temp volume from snapshot', client.volumes,
                arguments=dict(
                    size=snapshot.size, snapshot_id=snapshot.id,
                    name='tmp '+name,
                    description='Temporary volume for backup',
                    metadata=volume.metadata), resources=(snapshot,))

            # Backup temporary volume
            backup = self._create_and_wait(
                'Doing the actual backup', client.backups,
                arguments=dict(
                    volume_id=tmp_vol.id, name=name, container=None,
                    description=str(description)),
                resources=(snapshot, tmp_vol))

            # Cleanup temporary resources
            _LI('Deleting temporary volume and snapshot')
            tmp_vol.delete()
            snapshot.delete()

        elif volume.status == 'available':
            backup = self._create_and_wait(
                'Creating direct backup', client.backups,
                arguments=dict(
                    volume_id=volume.id, name=name, container=None,
                    description=str(description)))

        else:
            _LE("We don't backup volume because status is %s", volume.status)
            raise UnexpectedStatus(what=volume)

        return backup

    def _is_auto_backup(self, backup):
        """Check if a backup was created by us."""
        # It must have the right prefix
        if not backup.name or not backup.name.startswith(self.name_prefix):
            return False

        # And description must contain json formatted data base64 encoded
        try:
            BackupInfo(backup)
        except ValueError:
            return False
        return True

    def existing_backups(self, all_tenants=True):
        """Retrieve existing backups and return a defaultdict with backups
        grouped by original volume id."""
        # Get list of backups from Cinder Backup service
        backups = self.client.backups.list(**self._list_arguments(all_tenants))

        # Leave only automatic backups based on the backup name
        backups = filter(self._is_auto_backup, backups)

        # Dictionary of volumes with the list of backups for each one
        volumes = defaultdict(list)
        for backup in backups:
            backup.created_at_dt = datetime.strptime(backup.created_at,
                                                     '%Y-%m-%dT%H:%M:%S.%f')
            volumes[backup.name[len(self.name_prefix):]].append(backup)

        # Order the backups for each volume oldest first
        for volume in volumes.itervalues():
            volume.sort(key=attrgetter('created_at_dt'))

        return volumes

    def _restore_and_wait(self, client, backup_id, new_volume_id):
        # Restore the backup
        restore = client.restores.restore(backup_id=backup_id,
                                          volume_id=new_volume_id)

        volume = client.volumes.get(restore.volume_id)
        result = self._wait_for(volume, ('restoring-backup',), 'available',
                                True)
        return result

    def restore_volume(self, backup, keep_tenant, restore_id, restore_data):
        """Restore a specific backup

        :param backup: Backup object to restore
        :param keep_tenant: If we want to restore original tenant
        :param restore_id: If we want to restore to the original volume id
        :param restore_data: Restore original volume name and description
        :return: None
        """
        # Decode original volume information from backup object's description
        backup_info = BackupInfo(backup)

        # If we want to restore the id the volume must exist
        if restore_id:
            try:
                volume = self.client.volumes.get(backup_info.id)
                if volume.status != 'available':
                    _LW('Skipping, cannot restore to a non-available volume')
                    return
            except client.exceptions.NotFound:
                _LW("Skipping, destination id doesn't exist")
                return
            except client.exceptions.ClientException as e:
                _LW('Error when checking volume (%s)', e)
                return
            new_id = backup_info.id
        # If we don't give a new id one will be auto generated
        else:
            new_id = None

        # If we have to restore the tenant we need a different client
        tenant_client = self.get_client(backup_info.owner_tenant_id,
                                        keep_tenant)

        # Restore the backup
        restore = self._restore_and_wait(tenant_client, backup.id, new_id)

        # Recover volume name and description
        if restore_data:
            restore.update(name=backup_info.name,
                           description=backup_info.description)
        else:
            restore.update(description='auto_restore_' + backup_info.id + '_' +
                           backup_info.name)

    def restore_all(self, all_tenants=True, keep_tenant=True, restore_id=False,
                    restore_data=True, volume_id=None, backup_id=None):
        """Restore volumes.

        :param all_tenants: Restore volumes created by any tenant
        :param keep_tenant: Restore the volumes' tenants
        :param restore_id: We want to restore volumes to their original ids
        :param restore_data: We want to restore volume names and descriptions
        :param volume_id: Restore a specific volume id (cannot be used together
                          with backup_id)
        :param backup_id: Restore a specific backup_id (cannot be used together
                          with volume_id)
        """
        _LI('Starting Volumes Restore')
        backups = self.existing_backups(all_tenants=all_tenants)

        # If we want to get a specific volume's backup
        if volume_id:
            backup = backups.get(volume_id)
            if not backup:
                _LE('no backups for volume %s', volume_id)
                exit(1)

            # Fake that this is the only volume with backups
            backups = {volume_id: backups[volume_id]}

        # If we want a specific backup
        elif backup_id:
            # Look for it in the volumes
            for vol, backs in backups.iteritems():
                back = filter(lambda b: b.id == backup_id, backs)
                # If we find it fake that this is the only backup
                if back:
                    backups = {vol: [back]}
                    break
            else:
                _LE("backup doesn't exist")
                exit(1)

        for volume_id in backups:
            # Get the latest backup
            backup = backups[volume_id][-1]
            _LI('Processing %dGB from volume id %s in backup %s', backup.size,
                volume_id, backup.id)

            try:
                self.restore_volume(backup, keep_tenant=keep_tenant,
                                    restore_id=restore_id,
                                    restore_data=restore_data)
            except BackupIsDown:
                raise
            except Exception as exc:
                _LE('Exception while restoring backup: %s', exc)

            _LI('Restore completed')
        _LI('Finished with restores')

    def export_metadata(self, filename, all_tenants=False):
        """Export backup metadata to a file."""
        _LI('Exporting metadata to %s', filename)
        existing_backs = self.existing_backups(all_tenants=all_tenants)
        # Flatten the lists
        backups = [back for backs in existing_backs.itervalues()
                   for back in backs
                   if back.status not in ('deleting', 'error')]

        metadatas = []
        for back in backups:
            try:
                metadata = self.client.backups.export_record(back.id)
            except Exception as e:
                _LE('Error getting metadata for backup %(id)s (%(exception)s)',
                    {'id': back.id, 'exception': e})
            else:
                backup_info = BackupInfo(back)
                metadatas.append({'metadata': metadata,
                                  'tenant': backup_info.owner_tenant_id})

        try:
            with open(filename, 'w') as f:
                json.dump(metadatas, f)
        except Exception as e:
            _LE('Error saving metadata to %(filename)s (%(exception)s)',
                {'filename': filename, 'exception': e})

    def get_client(self, tenant_id, keep_tenant=True):
        """Return a client for requested tenant"""
        # If we are the original tenant of the volume
        if (not keep_tenant or
                self.client.client.auth_ref['token']['tenant']['id']
                == tenant_id):
            return self.client

        _LI("Using tenant id %s", tenant_id)
        return client.Client(version=2,
                             username=self.username,
                             api_key=self.api_key,
                             tenant_id=tenant_id,
                             auth_url=self.auth_url)

    def import_metadata(self, filename):
        """Import backup metadata to DB from file."""
        _LI('Importing metadata from %s', filename)
        try:
            with open(filename, 'r') as f:
                records = json.load(f)
        except Exception as e:
            _LE('Error loading from file %(filename)s (%(exception)s)',
                {'filename': filename, 'exception': e})
            return False

        for data in records:
            # Select client to use
            client = self.get_client(data['tenant'])

            try:
                client.backups.import_record(**data['metadata'])
            except Exception as e:
                _LE('Error importing record %s', data['metadata'])
                return False

        return True

    def list_backups(self, all_tenants=False):
        def _separator(separator):
            return (separator * (19+1) +
                    '+' + separator * (1+36+1) +
                    '+' + separator * (1+36+1) +
                    '+' + separator * (1+9+1) +
                    '+' + separator * (1+4+1))

        backups = self.existing_backups(all_tenants)
        format = '{:^19s} | {:^36} | {:^36} | {:^9} | {:5}'
        print format.format('Created at', 'Volume ID', 'Backup ID', 'Status',
                            'Size')
        print(_separator('='))
        mid_separator = _separator('-')
        for volume_id in backups:
            for backup in backups[volume_id]:
                print format.format(str(backup.created_at_dt), volume_id,
                                    backup.id, backup.status, backup.size)
            print mid_separator


def main(args):
    backup = BackupService(username=args.username,
                           api_key=args.password,
                           project_id=args.tenant_name,
                           auth_url=args.auth_url,
                           max_secs_gbi=getattr(args, 'max_secs_gbi', None))

    if not backup.is_up:
        _LC('Cinder Backup is ' + backup.backup_status)
        exit(1)

    if args.action == LIST:
        backup.list_backups(all_tenants=args.all_tenants)

    elif args.action == EXPORT:
        backup.export_metadata(filename=args.filename,
                               all_tenants=args.all_tenants)

    elif args.action == IMPORT:
        backup.import_metadata(filename=args.filename)

    elif args.action == BACKUP:
        failed = True
        try:
            __, failed = backup.backup_all(all_tenants=args.all_tenants,
                                           keep_tenant=args.keep_tenants,
                                           keep_only=args.keep_only)
        except BackupIsDown:
            _LC('Cinder Backup is ' + backup.backup_status)

        if args.filename:
            backup.export_metadata(filename=args.filename,
                                   all_tenants=args.all_tenants)

        if failed:
            exit(1)

    else:  # if args.action == RESTORE:
        # TODO look if metadata from other tenants is restored correctly
        # (they can see it)
        if args.filename:
            if not backup.import_metadata(filename=args.filename):
                return
            # Give it a little time to update the DB
            time.sleep(1)

        backup.restore_all(all_tenants=args.all_tenants,
                           keep_tenant=args.keep_tenants,
                           restore_id=args.restore_id,
                           restore_data=args.restore_data,
                           volume_id=args.volume_id,
                           backup_id=args.backup_id)

if __name__ == '__main__':
    parser = get_arg_parser()
    args = parser.parse_args()
    __ = create_logger(quiet=args.quiet)

    required = {'username': '--os-username or env[OS_USERNAME]',
                'password': '--os-password or env[OS_PASSWORD]',
                'tenant_name': '--os-tenant-name or env[OS_TENANT_NAME]',
                'auth_url': '--os-auth-url or env[OS_AUTH_URL]'}
    missing = {k: v for k, v in required.iteritems()
               if not getattr(args, k, None)}
    if missing:
        _LE('You must provide %s', ', '.join(required.itervalues()))
    else:
        main(args)
