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
from datetime import datetime
import json
import logging
from operator import attrgetter
import os
import sys
import time

import pdb

from cinderclient import client
from cinderclient import v2

VERSION = '0.1'

class tty_colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class BackupInfo(object):
    def __init__(self, data):
        if isinstance(data, str):
            self.__dict__ = json.loads(base64.b64decode(data))
        elif isinstance(data, v2.volume_backups.VolumeBackup):
            self.__dict__ = json.loads(
                base64.b64decode(data.description))
        elif isinstance(data, v2.volumes.Volume):
            self.id = data.id
            self.owner_tenant_id = getattr(data,
                                           'os-vol-tenant-attr:tenant_id')
            self.name = data.name
            self.description = data.description
        else:
            raise ValueError('data argument is of unknown class %s',
                             type(data))

    def __repr__(self):
        return base64.b64encode(json.dumps(self.__dict__))


class NotAvailable(Exception):
    def __init__(self, what, *args, **kwargs):
        super(NotAvailable, self).__init__(*args, **kwargs)
        self.what = what

class BackupService(object):
    default_poll_deplay=10

    def __init__(self, username, api_key, project_id, auth_url,
                 poll_delay=None, name_prefix='auto_backup_'):
        super(BackupService, self).__init__()
        self.username = username
        self.api_key = api_key
        self.project_id = project_id
        self.auth_url = auth_url
        self.poll_delay = poll_delay or self.default_poll_deplay
        self.name_prefix = name_prefix

        self.client = client.Client(version=2,
                                    username=username,
                                    api_key=api_key,
                                    project_id=project_id,
                                    auth_url=auth_url)
        self.status_msg = ''


    @property
    def backup_status(self):
        return self.status_msg

    @property
    def is_up(self):
        #Check that backup service is up and running
        try:
            services = self.client.services.list()

        # If policy doesn't allow us to check we'll have to assume it's there
        except client.exceptions.Forbidden:
            return True

        for service in services:
            if service.binary == 'cinder-backup':
                if service.state != 'up':
                    self.status_msg = service.state
                    return False
                if service.status != 'enabled':
                    self.status_msg = service.status
                    if service.disabled_reason:
                        self.status_msg += ' (%s)' % service.disabled_reason
                    return False
                return True

        self.status_msg = "Not loaded"
        return False

    def backup_all(self, all_tenants=True, keep_tenant=True, keep_only=0):
        backups = []
        volumes = self.client.volumes.list(search_opts=
                                           {'all_tenants':all_tenants})
        existing_backups = self.existing_backups(all_tenants=all_tenants)
        _LI('Starting Volumes Backup')
        for vol in volumes:
            vol_name = vol.name or vol.id
            _LI(tty_colors.HEADER + 'Processing volume ' + vol_name +
                tty_colors.ENDC)
            backup_name = self.name_prefix + vol.id

            owner_tenant_id = getattr(vol, 'os-vol-tenant-attr:tenant_id')
            same_tenant = (self.client.client.auth_ref['token']['tenant']['id']
                           == owner_tenant_id)
            if keep_tenant and not same_tenant:
                _LI("Using owner's tenant")
                tenant_client= client.Client(version=2,
                                             username=self.username,
                                             api_key=self.api_key,
                                             tenant_id=owner_tenant_id,
                                             auth_url=self.auth_url)
            else:
                tenant_client = self.client

            backup = self.backup_volume(vol, name=backup_name,
                                        client=tenant_client)

            if backup:
                backups.append(backup)
                existing_backups[vol.id].append(backup)
                # If we limit the number of backups and we have too many
                # backups for this volume
                if (keep_only and
                    len(existing_backups.get(vol.id, tuple())) > keep_only):
                    _LI('Removing old backups')
                    remove = len(existing_backups[vol.id]) - keep_only
                    for __ in xrange(remove):
                        back = existing_backups[vol.id].pop(0)
                        # Todo this could fail and we have to wait
                        back.delete()
            _LI('Backup completed')
        _LI('Finished with backups')
        return backups

    def _create_and_wait(self, msg, module, arguments):
        creator = getattr(module, 'create')
        getter = getattr(module, 'get')

        _LI(msg)
        result = creator(**arguments)
        while result.status == 'creating':
            time.sleep(self.poll_delay)
            result = getter(result.id)

        if result.status != 'available':
            raise NotAvailable(what=result)

        return result


    def backup_volume(self, volume, name=None, description=None, client=None):
        if isinstance(volume, str):
            # TODO: This could fail
            volume = self.client.volumes.get(volume)

        client = client or self.client
        name = name or self.name_prefix + volume.id
        description = description or BackupInfo(volume)

        if volume.status == 'in-use':
            _LI('Volume online so this is a multi-step process')

            #Force snapshot since volume it's in-use
            try:
                snapshot = self._create_and_wait(
                    'Creating snapshot', client.volume_snapshots,
                    arguments=dict(
                        volume_id=volume.id, force=True, name='tmp ' + name,
                        description='Temporary snapshot for backup',
                        metadata=volume.metadata))
            except NotAvailable as e:
                _LE('error creating snapshot')
                e.what.delete()
                return None

            #Force snapshot since volume it's in-use
            try:
                tmp_vol = self._create_and_wait(
                    'Creating temp volume from snapshot', client.volumes,
                    arguments=dict(
                        size=snapshot.size, snapshot_id=snapshot.id,
                        name='tmp '+name,
                        description='Temporary volume for backup',
                        metadata=volume.metadata))
            except NotAvailable as e:
                _LE('error creating temp volume from snapshot')
                snapshot.delete()
                e.what.delete()
                return None

            try:
                backup = self._create_and_wait(
                    'Doing the actual backup', client.backups,
                    arguments=dict(
                        volume_id=tmp_vol.id, name=name, container=None,
                        description=str(description)))

            except NotAvailable as e:
                _LE('error creating backup')
                backup.delete()
                return None
            finally:
                snapshot.delete()
                tmp_vol.delete()

        elif volume.status == 'available':
            try:
                backup = self._create_and_wait(
                    'Creating direct backup', client.backups,
                    arguments=dict(
                        volume_id=volume.id, name=name, container=None,
                        description=str(description)))

            except NotAvailable as e:
                _LE('error creating backup')
                backup.delete()
                return None

        else:
            _LE("We don't backup volume because status is %s", volume.status)
            return None

        # TODO check if we

        return backup

    def _is_auto_backup(self, backup):
        # It must have the right prefix
        if not backup.name.startswith(self.name_prefix):
            return False

        # And description must contain json formatted data base64 encoded
        try:
            BackupInfo(backup)
        except ValueError:
            return False
        return True

    def existing_backups(self, all_tenants=True):
        # Get list of backups from Cinder Backup service
        backups = self.client.backups.list(search_opts=
                                           {'all_tenants': all_tenants})

        # Leave only automatic backups based on the backup name
        backups = filter(self._is_auto_backup, backups)

        # Dictionary of volumes with the list of backups for each one
        volumes = defaultdict(list)
        for backup in backups:
            backup.created_at_dt = datetime.strptime(backup.created_at,
                                                    "%Y-%m-%dT%H:%M:%S.%f")
            volumes[backup.name[len(self.name_prefix):]].append(backup)

        # Order the backups for each volume
        for volume in volumes.itervalues():
            volume.sort(key=attrgetter('created_at_dt'))

        return dict(volumes)

    def restore_volume(self, backup, keep_tenant, restore_id, restore_data):
        backup_info = BackupInfo(backup)

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
        else:
            new_id = None

        same_tenant = (self.client.client.auth_ref['token']['tenant']['id']
                       == backup_info.owner_tenant_id)

        if keep_tenant and not same_tenant:
            _LI("Using owner's tenant")
            tenant_client= client.Client(version=2,
                                         username=self.username,
                                         api_key=self.api_key,
                                         tenant_id=backup_info.owner_tenant_id,
                                         auth_url=self.auth_url)
        else:
            tenant_client = self.client

        restore = tenant_client.restores.restore(backup_id=backup.id,
                                                 volume_id=new_id)

        if not restore_id:
            new_id = restore.volume_id

        volume = tenant_client.volumes.get(new_id)
        # Wait for the restoration to complete
        while volume.status != 'available':
            time.sleep(self.poll_delay)
            volume = tenant_client.volumes.get(new_id)

        # Recover volume name and description
        if restore_data:
            volume.update(name=backup_info.name,
                          description=backup_info.description)
        else:
            volume.update(description='auto_restore_' + backup_info.id + '_' +
                                      backup_info.name)

    def restore_all(self, all_tenants=True, keep_tenant=True, restore_id=False,
                    restore_data=True, volume_id=None, backup_id=None):
        _LI('Starting Volumes Restore')
        backups = self.existing_backups(all_tenants=all_tenants)

        if volume_id:
            backup = backups.get(volume_id)
            if not backup:
                _LE('no backups for volume %s', volume_id)
                exit(1)

            backups = {volume_id: backups[volume_id]}
        elif backup_id:
            for vol, backs in backups.iteritems():
                if backup_id in map(attrgetter('id'), backs):
                    backups = {vol: backs}
                    break
            else:
                _LE("backup doesn't exist")
                exit(1)

        for volume_id in backups:
            # Get the latest backup
            backup = backups[volume_id][-1]
            _LI(tty_colors.HEADER + 'Processing volume ' + volume_id +
                tty_colors.ENDC)

            self.restore_volume(backup, keep_tenant=keep_tenant,
                                restore_id=restore_id,
                                restore_data=restore_data)
            _LI('Restore completed')
        _LI('Finished with restores')

    def export_metadata(self, filename, all_tenants=False):
        existing_backs = self.existing_backups(all_tenants=all_tenants)
        # Flatten the lists
        backups = [back for backs in existing_backs.itervalues()
                   for back in backs]

        metadatas = []
        for back in backups:
            #TODO add try
            metadata = self.client.backups.export_record(back.id)
            metadatas.append(metadata)

        # TODO add try
        with open(filename, 'w') as f:
            json.dump(metadatas, f)

    def import_metadata(self, filename):
        with open(filename, 'r') as f:
            records = json.load(f)

        for metadata in records:
            self.client.backups.import_record(**metadata)

def create_logger(quiet=False):
    global _LI, _LW, _LE, _LC

    logger = logging.getLogger(__name__)

    logger.setLevel(logging.WARNING if quiet else logging.INFO)

    # create console handler and set level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # create formatter for ch
    formatter = logging.Formatter('%(levelname)s:%(message)s')
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    _LI = logger.info
    _LW = logger.warning
    _LE = logger.error
    _LC = logger.critical

    return logger

BACKUP = 'backup'
RESTORE = 'restore'
LIST = 'list'
EXPORT = 'export'
IMPORT = 'import'

def get_arg_parser():
    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            sys.stderr.write('\nerror: %s\n' % message)
            sys.exit(2)

    parser = MyParser(description='Cinder auto backup management tool',
                      epilog='epilog', version=VERSION,
                      add_help=True)
    parser.add_argument('-a', '--all-tenants', dest='all_tenants',
                        action='store_true', default=False,
                        help='include volumes/backups from all tenants'
                             '(default only from supplied tenant)')
    parser.add_argument('--os-username', metavar='<auth-user-name>',
                        dest='username', default=os.environ['OS_USERNAME'],
                        help='OpenStack user name. Default=env[OS_USERNAME]')
    parser.add_argument('--os-password', metavar='<auth-password>',
                        dest='password', default=os.environ['OS_PASSWORD'],
                        help='Password for OpenStack user. '
                            'Default=env[OS_PASSWORD]')
    parser.add_argument('--os-tenant-name', metavar='<auth-tenant-name>',
                        dest='tenant_name',
                        default=os.environ['OS_TENANT_NAME'],
                        help='Tenant name. Default=env[OS_TENANT_NAME]')
    parser.add_argument('--os-auth-url', metavar='<auth-url>', dest='auth_url',
                        default=os.environ['OS_AUTH_URL'],
                        help='URL for the authentication service. '
                             'Default=env[OS_AUTH_URL]')
    parser.add_argument('-q', '--quiet', dest='quiet',
                        default=False, action='store_true',
                        help='No output except warnings or errors')

    subparsers = parser.add_subparsers(title='actions', dest='action',
                                       help='action to perform')

    parser_export = subparsers.add_parser(EXPORT, help='export metadata')
    parser_export.add_argument('filename', metavar='<FILENAME>',
                               help='file to export to')

    parser_export = subparsers.add_parser(IMPORT, help='import metadata')
    parser_export.add_argument('filename',  metavar='<FILENAME>',
                               help='file to import from')

    parser_list = subparsers.add_parser(LIST, help='list available automatic '
                                                   'backups')

    # This argument will be for backup and restore
    forget_tenants=dict(dest='keep_tenants', action='store_false',
                        default=True, help="don't make backups available to "
                        "original tenant (default available)")

    parser_backup = subparsers.add_parser(BACKUP, help='do backups')
    parser_backup.add_argument('--export-metadata', dest='filename',
                               default=None,  metavar='<FILENAME>',
                               help='export all auto backup metadata to file')
    parser_backup.add_argument('--forget-tenants', **forget_tenants)
    parser_backup.add_argument('--keep-only', dest='keep_only', default=0,
                               metavar='<#>',
                               type=int, help='how many automatic backups to '
                                              'keep, oldest ones will be '
                                              'deleted (default keep all)')

    parser_restore = subparsers.add_parser(RESTORE, help='restore backups',
                                           epilog='Restore last backup')

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


def main(args):
    backup = BackupService(username=args.username,
                           api_key=args.password,
                           project_id=args.tenant_name,
                           auth_url=args.auth_url)

    if not backup.is_up:
        _LC('Cinder Backup is ' + backup.backup_status)
        exit(1)

    if args.action == BACKUP:
        backup.backup_all(all_tenants=args.all_tenants,
                          keep_tenant=args.keep_tenants,
                          keep_only=args.keep_only)
        if args.filename:
            backup.export_metadata(filename=args.filename,
                                   all_tenants=args.all_tenants)

    elif args.action == LIST:
        backups = backup.existing_backups(all_tenants=args.all_tenants)
        format = '{:^19s} | {:^36} | {:^36} | {:5}'
        print format.format('Created at', 'Volume ID', 'Backup ID', 'Size')
        print('=' * (19+1) +
              '+' + '=' * (1+36+1) +
              '+' + '=' * (1+36+1) +
              '+' + '=' * (1+4+1))
        for volume_id in backups:
            for backup in backups[volume_id]:
                print format.format(str(backup.created_at_dt), volume_id,
                                    backup.id, backup.size)
            print('-' * (19+1) +
                  '+' + '-' * (1+36+1) +
                  '+' + '-' * (1+36+1) +
                  '+' + '-' * (1+4+1))

    elif args.action == RESTORE:
        # TODO look if metadata from other tenants is restored correctly
        # (they can see it)
        if args.filename:
            backup.import_metadata(filename=args.filename)

        backup.restore_all(all_tenants=args.all_tenants,
                           keep_tenant=args.keep_tenants,
                           restore_id=args.restore_id,
                           restore_data=args.restore_data,
                           volume_id=args.volume_id,
                           backup_id=args.backup_id)

    elif args.action == EXPORT:
        backup.export_metadata(filename=args.filename,
                               all_tenants=args.all_tenants)

    else:
        backup.import_metadata(filename=args.filename)


if __name__ == '__main__':
    parser = get_arg_parser()
    args = parser.parse_args()
    __ = create_logger(quiet=args.quiet)
    main(args)
