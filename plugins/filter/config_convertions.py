

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import collections

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  merge_dicts, \
  setdefault_none

from ansible.utils.display import Display


display = Display()


##
## Further zenko docker json cfgfiles sub config fine tuning post
## normalisation with one main point beeing merging
## created / cycled credentials into it
##
class ZenkoDockerJsonCfgFilesFilter(FilterBase):

    FILTER_ID = 'zenko_docker_json_cfgfiles'

    @property
    def argspec(self):
        tmp = super(ZenkoDockerJsonCfgFilesFilter, self).argspec

        tmp.update({
          'credmap': ([collections.abc.Mapping], {}),
        })

        return tmp


    def _handle_cfgfile_auth_config(self, subcfg):
        credmap = self.get_taskparam('credmap')

        for acc in subcfg['settings']['accounts']:
            for akey in acc.get('keys', []):
                ckey = akey['access']
                cred_x = credmap.get(ckey, None)

                if cred_x:
                    akey['secret'] = cred_x['password']


    def run_specific(self, inlist):
        if not isinstance(inlist, list):
            raise AnsibleOptionsError(
               "filter input must be a list type, but given value"\
               " '{}' has type '{}'".format(inlist, type(inlist))
            )

        for x in inlist:
          spec_fn = getattr(self, '_handle_cfgfile_' + x['config_id'], None)

          if spec_fn:
              spec_fn(x)

        return inlist


##
## Re-adds freshly created / updated secrets to role config
##
class ZenkoDockerCredsToCfgFilter(FilterBase):

    FILTER_ID = 'zenko_docker_creds_to_cfg'

    @property
    def argspec(self):
        tmp = super(ZenkoDockerCredsToCfgFilter, self).argspec

        tmp.update({
          'credmap': ([collections.abc.Mapping], {}),
        })

        return tmp

    def run_specific(self, indict):
        if not isinstance(indict, MutableMapping):
            raise AnsibleOptionsError(
               "filter input must be a mapping type, but given value"\
               " '{}' has type '{}'".format(indict, type(indict))
            )

        credmap = self.get_taskparam('credmap')
        users = indict

        for x in ['users', 'users']:
            users = users.get(x, None)

            if not users:
                break

        if credmap and users:
            ## re-add creds to users
            ##
            ## note: when creating the original config all of these
            ##   submaps use the same identical user subdict (same object),
            ##   so updating it once should be enough, but somehow when
            ##   loading/saving the config as ansvars this get lost (is
            ##   this cfg map reparsed by ansible multiple times??),
            ##   meaning that currently we must update all the places
            ##   one by one
            ##
            upd_maps = [users, indict['users']['users_by_name']]

            dummy_tmp_map = {}

            ba_admin = indict['users'].get('bucket_admin', None)

            if ba_admin:
                dummy_tmp_map['__bucket_adm_dummy_user__'] = ba_admin

            admin_defcreds = indict['users'].get('default_admin_creds', None)

            if admin_defcreds:
                dummy_tmp_map['__defcreds_dummy_user__'] = {
                  'config': {'keys': [admin_defcreds]},
                }

            if dummy_tmp_map:
                upd_maps.append(dummy_tmp_map)

            for cmap in upd_maps:
                for ku, uv in cmap.items():
                    for akx in uv['config']['keys']:
                        pwhit = credmap.get(akx['access'], None)

                        if pwhit:
                            akx['secret'] = pwhit['password']

            bcheck_cfgs = indict

            for x in ['s3_frontend', 'buckets', '_export_cfgs', 'excludes']:
                bcheck_cfgs = bcheck_cfgs.get(x, None)

                if not bcheck_cfgs:
                    break

            for x in (bcheck_cfgs or []):
                bcx = x['get_buckets_cfg']
                bcx2 = x['delete_bad_buckets_cfg']

                pwhit = credmap.get(bcx['access_key'], None)

                if pwhit:
                    bcx['secret_key'] = pwhit['password']
                    bcx2['secret_key'] = pwhit['password']

            if admin_defcreds:
                ## optionally expose default admin creds as env vars
                ## for further api based configurations
                indict['_export_cfgs']['cfg_env']['AWS_ACCESS_KEY'] =\
                  admin_defcreds['access']

                indict['_export_cfgs']['cfg_env']['AWS_SECRET_KEY'] =\
                  admin_defcreds['secret']

        return indict



# ---- Ansible filters ----
class FilterModule(object):
    ''' config convertion filter for this collection '''

    def filters(self):
        res = {}

        tmp = [
          ZenkoDockerJsonCfgFilesFilter,
          ZenkoDockerCredsToCfgFilter,
        ]

        for f in tmp:
            res[f.FILTER_ID] = f()

        return res

