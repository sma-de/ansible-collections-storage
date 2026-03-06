
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import collections
import copy
import json
import os
import pathlib
import textwrap
##import uuid

from urllib.parse import urlparse

from ansible.errors import AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import\
  ConfigNormalizerBaseMerger,\
  NormalizerBase, NormalizerNamed,\
  DefaultSetterConstant, DefaultSetterOtherKey

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.web_service import\
  SecureConnectionNormer

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  setdefault_none, SUBDICT_METAKEY_ANY, get_subdict, merge_dicts

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



display = Display()



def to_azure_endpoint_url(acc_name):
    return "https://{}.blob.core.windows.net".format(acc_name)


def norm_name_s3(name):
    ## convert various unsupported special chars to safe special char "-"
    for x in ['_']:
        name = name.replace(x, '-')

    return name


def norm_name_azure_store_acc(name):
    ## at least for storage accounts azure seems to
    ## basically forbid any kind of special char,
    ## so just remove them if you see some
    for x in ['_', '-', '.']:
        name = name.replace(x, '')

    return name



class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'azcollection_requirements_srcpath', DefaultSetterConstant(
             'ansible_collections/azure/azcollection/requirements-azure.txt'
          )
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          (SslCertsNormer, True),
          DockerCfgNormer(pluginref),
          StorageBackendsRootNormer(pluginref),
          UserRootNormer(pluginref),
          S3FrontendNormer(pluginref),
          MetricsNormer(pluginref),
          DockerCfgServiceRevProxyPostNormer(pluginref),
          CfgFilesPassesNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'collections_basepath',
          os.environ.get('ANSIBLE_COLLECTION_DIR',
            './collections'
          ) # on default use cwd
        )

        reqsrc = my_subcfg['azcollection_requirements_srcpath']

        if not os.path.isabs(reqsrc):
            my_subcfg['azcollection_requirements_srcpath'] = os.path.join(
              my_subcfg['collections_basepath'], reqsrc
            )

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        exp_cfgs = {}

        ## create fitting configs for all dirs which must exist
        dir_ccfgs = {}

        tmp = my_subcfg['docker']['dirs'].get('_local', None)
        if tmp:
            dir_ccfgs = copy.deepcopy(tmp)

        for k, v in my_subcfg['cfgfiles'].items():
            if not v['file_config']:
                continue

            fc = copy.deepcopy(v['file_config'])
            fc['path'] = str(pathlib.Path(fc.pop('dest')).parent)

            if fc['path'] in dir_ccfgs:
                continue

            dir_ccfgs[fc['path']] = fc

        for x in dir_ccfgs.values():
            x['state'] = 'directory'

        exp_cfgs['dirs_create'] = list(dir_ccfgs.values())

        ## create fitting configs to template json config files
        json_cfgfiles = []

        for k, v in my_subcfg['cfgfiles'].items():
            if k in ['reverse_proxy']:
                ## ignore non-json configs
                continue

            if not v['settings']:
                ## ignore empty config file
                continue

            json_cfgfiles.append(v)

        exp_cfgs['json_cfgfiles'] = json_cfgfiles

        exp_cfgs['cfg_env'] = {}

        conn = my_subcfg.get('connection', {})
        tmp = conn.get('s3api_url', None)

        if tmp:
            exp_cfgs['cfg_env']['AWS_URL'] = tmp

        my_subcfg['_export_cfgs'] = exp_cfgs
        return my_subcfg


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='zenko',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )



class SslCertsNormer(NormalizerBase):

    NORMER_CONFIG_PATH = ['ssl_certs']

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'certs',
          DefaultSetterConstant({})
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SslCertsInstNormer(pluginref),
        ]

        super(SslCertsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        dc = my_subcfg.get('default_certs', None)

        if dc:
            my_subcfg['certs']['default_certs'] = dc

        return my_subcfg


class SslCertsInstNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SslCertsInstCertFileNormer(pluginref),
          SslCertsInstKeyFileNormer(pluginref),
        ]

        super(SslCertsInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['certs', SUBDICT_METAKEY_ANY]


class SslCertsInstFileBaseNormer(NormalizerBase):

    @property
    def simpleform_key(self):
        return 'local_path'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'target_path', my_subcfg['local_path'])
        return my_subcfg


class SslCertsInstCertFileNormer(SslCertsInstFileBaseNormer):

    @property
    def config_path(self):
        return ['cert_file']


class SslCertsInstKeyFileNormer(SslCertsInstFileBaseNormer):

    @property
    def config_path(self):
        return ['key_file']



class MetricsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'port', DefaultSetterConstant(8002)
        )

        self._add_defaultsetter(kwargs,
          ## optional subpath to make this avaible on in reverse-proxy mode
          'proxy_path', DefaultSetterConstant('/metrics/')
        )

        self._add_defaultsetter(kwargs,
          'proxy_mode', DefaultSetterConstant('prefer_port')
          ##'proxy_mode', DefaultSetterConstant('prefer_path')
        )

        super(MetricsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['metrics']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## default and norm bind addresses
        baddr = setdefault_none(my_subcfg, 'bind_addresses', {})

        if not isinstance(baddr, collections.abc.Mapping):
            ## assume simple one address string
            baddr = {baddr: True}

        ## empty metrics on is totally fine
        ## if not baddr:
        ##     baddr['0.0.0.0'] = True

        bindings = {}

        for k, v in baddr.items():
            if v is None:
                v = {'enabled': True}
            elif not isinstance(v, collections.abc.Mapping):
                ## assume simple bool
                v = {'enabled': bool(v)}
            else:
                setdefault_none(v, 'enabled', True)

            if not v['enabled']:
                continue  # skip disabled baddr

            tmp = {}

            tmp['ip'] = setdefault_none(v, 'addr', k)
            tmp['port'] = setdefault_none(v, 'port', my_subcfg['port'])

            bindings["{ip}-{port}".format(**tmp)] = tmp

        ## forward defined s3 port to config file
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        for x in ['cfgfiles', 'config', 'settings']:
            pcfg = setdefault_none(pcfg, x, {})

        pcfg['metricsPort'] = my_subcfg['port']
        pcfg['metricsListenOn'] = list(bindings.values())

        ## also ensure port is mapped docker-wise when necessary
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        pcfg = pcfg['docker']['services']

        if not pcfg['reverse_proxy']['enabled']:
            pcfg = pcfg['cloudserver']['templates']['templates']

            pcfg['_cfg_metric_settings'] = {
              'ports': ["{0}:{0}".format(my_subcfg['port'])]
            }

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        conn = pcfg.get('connection', {})

        if conn.get('url', None):
            ## create metrics url when connection is defined
            murl = ""

            if conn['scheme']:
                murl = conn['scheme'] + '://'

            murl += conn['host']

            has_path = bool(my_subcfg['proxy_path'])
            use_path = my_subcfg['proxy_mode'] in ['prefer_path', 'both']

            if has_path and use_path:
                if my_subcfg['proxy_path'] != '/':
                    murl += my_subcfg['proxy_path']
            else:
                ## use metrics port
                murl += ':' + str(my_subcfg['port'])

            conn['metrics_url'] = murl

        return my_subcfg



class UserRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'num_start_id', DefaultSetterConstant(10000)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserMapNormer(pluginref),
        ]

        super(UserRootNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['users']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        cfg_accs = []
        creds_cfg = {}
        creds_to_user = {}
        exp_cfgs = {}

        bucket_admins = {}
        users_by_name = {}
        ##access_to_user = {}

        short_id_doubles = {}
        long_id_doubles = {}

        cur_def_sid = my_subcfg['num_start_id']

        for k, v in my_subcfg['users'].items():
            tmp = users_by_name.get(v['name'], {})
            ansible_assert(not tmp,
               "bad user subconfig, at least two users with mapping"\
               " keys {} have the same name defined '{}', this"\
               " is bad".format([tmp.get('mapkey', None), v['mapkey']],
                  v['name']
               )
            )

            if v['bucket_admin']:
                if bucket_admins:
                    ansible_assert(False,
                       "bad user subconfig, at least two users with"\
                       " mapping keys {} are marked as 'bucket_admin', but"\
                       " there can ever be maximal one bucket admin".format(
                          [next(iter(bucket_admins.values())).get('mapkey'),
                           v['mapkey']
                          ]
                       )
                    )

                bucket_admins[v['name']] = v

            users_by_name[v['name']] = v
            xc = v['config']

            sid = setdefault_none(xc, 'shortid', "{:012d}".format(
              cur_def_sid
            ))

            setdefault_none(xc, 'arn', "arn:aws:iam::{}:root".format(sid))
            othu = short_id_doubles.get(sid, None)

            ansible_assert(not othu,
               "bad user config, at least two users have the same"\
               " short-id:\n{}".format(v, othu)
            )

            short_id_doubles[sid] = v

            lid = setdefault_none(xc, 'canonicalID', "{}-{}".format(
              sid, v['name']
            ))

            othu = long_id_doubles.get(lid, None)

            ansible_assert(not othu,
               "bad user config, at least two users have the same"\
               " canonical-id:\n{}".format(v, othu)
            )

            long_id_doubles[lid] = v
            cfg_accs.append(xc)

            for ck, cv in v['credentials']['key_sets'].items():
                cred_k = cv['access_key']

                tmp = creds_to_user.get(cred_k, None)
                ansible_assert(not tmp,
                   "S3 access keys must be globally unique, but at least"\
                   " two users have the same access key '{}' defined:"\
                   " {}".format(cred_k, [tmp, '.'.join(cfgpath_abs + [k])])
                )

                creds_cfg[cred_k] = cv['config']
                creds_to_user[cred_k] = '.'.join(cfgpath_abs + [k])
                ##access_to_user[cred_k] = v

            cur_def_sid += 1

        if cfg_accs:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs)

            for x in ['cfgfiles', 'auth_config', 'settings']:
                pcfg = setdefault_none(pcfg, x, {})

            pcfg['accounts'] = cfg_accs

        if creds_cfg:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs)

            ## at least one user credential to auto cycle,
            ## create auto-cycle upstream config
            creds_cfg = { 'passwords': {
                'passwords': creds_cfg,
              },

              'hide_secrets': pcfg['hide_secrets'],
            }

            pw_defs = my_subcfg.get('pw_defaults', None)

            if pw_defs:
                creds_cfg['passwords']['pw_defaults'] = pw_defs

            exp_cfgs['user_creds'] = creds_cfg

        if exp_cfgs:
            my_subcfg['_export_configs'] = exp_cfgs

        my_subcfg['users_by_name'] = users_by_name
        ##my_subcfg['access_to_user'] = access_to_user
        my_subcfg['bucket_admin'] = None
        my_subcfg['default_admin_creds'] = None

        if bucket_admins:
            my_subcfg['bucket_admin'] = next(iter(bucket_admins.values()))
            my_subcfg['default_admin_creds'] = \
              my_subcfg['bucket_admin']['config']['keys'][0]

        return my_subcfg



class UserMapNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserInstNormer(pluginref),
        ]

        super(UserMapNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['users']



class UserInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'bucket_admin', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserInstPermNormer(pluginref),
          UserInstMailTemplateNormer(pluginref),
          UserCredsKeySetInstNormer(pluginref),
        ]

        super(UserInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['mapkey'] = cfgpath_abs[-1]

        c = setdefault_none(my_subcfg, 'config', {})

        c['name'] = my_subcfg['name']

        ## stupid idea: rerunning this config with the same input
        ## data would always give new canonical ideas and as
        ## such new users !!
        ##setdefault_none(c, 'canonicalID', str(uuid.uuid4()))

        arn = c.get('arn')

        if arn:
            arn2 = arn.split(':')
            sid = int(c.get('shortid', None) or arn2[4])

            ansible_assert(sid == int(arn2[4]),
               "Invalid user config '{}', shortid must match"\
               " user id in arn, but '{}' != '{}'".format(
                  '.'.join(cfgpath_abs), arn, sid
               )
            )

            c['shortid'] = "{:012d}".format(sid)

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## being bucket admin forces some permission settings
        if my_subcfg['bucket_admin']:
            my_subcfg['permissions']['bucket_create'] = True

        ## handle this users auto credentials
        cfg_keys = setdefault_none(my_subcfg['config'], 'keys', [])

        seen_access_key = {}

        for k, v in my_subcfg['credentials']['key_sets'].items():
            ansible_assert(v['access_key'] not in seen_access_key,
               "credential access key '{}' used more than once for user"\
               " '{}', but access key's must be unique".format(
                  v['access_key'], '.'.join(cfgpath_abs)
               )
            )

            cfg_keys.append({'access': v['access_key']})
            seen_access_key[v['access_key']] = True

        return my_subcfg



class UserInstMailTemplateNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'prefix', DefaultSetterConstant('')
        )

        self._add_defaultsetter(kwargs,
          'suffix', DefaultSetterConstant('')
        )

        super(UserInstMailTemplateNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['mail_template']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        ui = my_subcfg.get('user_id', None)

        if not ui:
            ui = pcfg['name'].replace('_', '-')
            my_subcfg['user_id'] = ui

        uc = setdefault_none(pcfg, 'config', {})

        if 'email' not in uc:
            uc['email'] = "{prefix}{user_id}{suffix}@{domain}".format(
              **my_subcfg
            )

        return my_subcfg



class UserInstPermNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'bucket_create', DefaultSetterConstant(True)
        )

        super(UserInstPermNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['permissions']



class UserCredsKeySetInstNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'user_as_access', DefaultSetterConstant(False)
        )

        super(UserCredsKeySetInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['credentials', 'key_sets', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        if my_subcfg['user_as_access']:
            my_subcfg['access_key'] = pcfg['name']
        ##else:
        ##    setdefault_none(my_subcfg, 'access_key', str(uuid.uuid4()))

        c = setdefault_none(my_subcfg, 'config', {})
        c['user'] = my_subcfg['access_key']

        ## enrich upstream store config with custom variables which
        ## might be useful for path templating and similar
        cred_defs = setdefault_none(c, 'credential', {})
        cred_defs = setdefault_none(cred_defs, 'store_defaults', {})
        cred_defs = setdefault_none(cred_defs, 'all', {})

        cred_defs = setdefault_none(cred_defs, 'parameters', {})
        cred_defs = setdefault_none(cred_defs, 'custom_vars_item', {})
        cred_defs = setdefault_none(cred_defs, my_subcfg['access_key'], {})

        cred_defs['username'] = pcfg['name']
        cred_defs['keyset_id'] = cfgpath_abs[-1] 

        return my_subcfg



class DockerCfgNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'compose_file', DefaultSetterConstant('docker-compose.yml')
        )

        self._add_defaultsetter(kwargs,
          'compose_file_pretext', DefaultSetterConstant(None)
        )

        self._add_defaultsetter(kwargs,
          'environment', DefaultSetterConstant({})
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DockerCfgComposeRootDirNormer(pluginref),
          DockerCfgServiceCloudServerNormer(pluginref),
          DockerCfgServiceRevProxyPreNormer(pluginref),
        ]

        super(DockerCfgNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['docker']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ccfg = setdefault_none(my_subcfg, 'compose_template', {})
        ccfg = setdefault_none(ccfg, 'config', {})

        ccfg['dest'] = my_subcfg['dirs']['compose_root']['path']\
                     + '/' + my_subcfg['compose_file']

        ##if ccfg.get('validate', None) is None:
        ##    ccfg['validate'] = \
        ##      "docker compose -f '%s' config -q".format(ccfg['dest'])

        if my_subcfg['compose_file_pretext'] is None:
            my_subcfg['compose_file_pretext'] = textwrap.dedent("""
               ##
               ## this file is auto generated by ansible,
               ## DO NOT EDIT MANUALLY!!
               ##
               """
            )

        if my_subcfg['compose_file_pretext']:
            my_subcfg['compose_file_pretext'] += '\n\n'

        is_building = False

        for k, v in my_subcfg['services'].items():
            is_building = v.get('is_building', False)

            if is_building:
                break

        my_subcfg['is_building'] = is_building
        return my_subcfg



class DockerCfgComposeRootDirNormer(NormalizerBase):

    @property
    def simpleform_key(self):
        return 'path'

    @property
    def config_path(self):
        return ['dirs', 'compose_root']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        p = my_subcfg.get('path', None)
        ansible_assert(p,
          "Must set mandatory config key '{}'".format(
             '.'.join(cfgpath_abs)
          )
        )

        c = setdefault_none(my_subcfg, 'config', {})
        c['path'] = p

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        dmap = setdefault_none(pcfg, '_local', {})
        tmp = my_subcfg['config']
        dmap[tmp['path']] = tmp

        return my_subcfg



class DockerCfgServiceNormerBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DockerCfgServiceDefTemplateNormer(pluginref),
          DockerCfgServiceDefTemplateFilesInstNormer(pluginref),
          DockerCfgServiceDefTemplateInstNormer(pluginref),
        ]

        super(DockerCfgServiceNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'container_name',
          my_subcfg['service_name']
        )

        my_subcfg['container_name'] = norm_name_s3(
          my_subcfg['container_name']
        )

        return my_subcfg



class DockerCfgServiceDefTemplateNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'use', DefaultSetterConstant(True)
        )

        super(DockerCfgServiceDefTemplateNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['templates', 'default_template']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['use']:
            return my_subcfg

        ## default path
        path = my_subcfg.get('path', None)

        if not path:
            rp = self.pluginref.get_ansible_var('role_path')

            path = "{}/templates/docker/services/{}.yml.j2".format(rp,
              cfgpath_abs[-3]
            )

            my_subcfg['path'] = path

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(pcfg, 'template_files', {}).update(
          default_template=path
        )

        return my_subcfg



class DockerCfgServiceDefTemplateFilesInstNormer(NormalizerBase):

    @property
    def simpleform_key(self):
        return 'path'

    @property
    def config_path(self):
        return ['templates', 'template_files', SUBDICT_METAKEY_ANY]



class DockerCfgServiceDefTemplateInstNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['templates', 'templates', SUBDICT_METAKEY_ANY]



class DockerCfgServiceRevProxyPreNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['services', 'reverse_proxy']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ena = setdefault_none(my_subcfg, 'enabled', bool(my_subcfg))

        if not ena:
            return my_subcfg

        setdefault_none(my_subcfg, 'service_name', cfgpath_abs[-1])
        return my_subcfg



class DockerCfgServiceRevProxyPostNormer(DockerCfgServiceNormerBase):

    @property
    def config_path(self):
        return ['docker', 'services', 'reverse_proxy']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['enabled']:
            return my_subcfg

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        tmpl_sets = {
          'container_name': my_subcfg['container_name'],
        }

        setdefault_none(tmpl_sets, 'depends_on', []).append(
          pcfg['cloudserver']['service_name']
        )

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        ## handle ssl certs volume mappings
        ssl_certs_lst = []
        for k, v in pcfg.get('ssl_certs', {}).get('certs', {}).items():
            for x in ['cert_file', 'key_file']:
               ssl_certs_lst.append("{}:{}:ro".format(
                 v[x]['local_path'], v[x]['target_path']
               ))

        if ssl_certs_lst:
            setdefault_none(tmpl_sets, 'volumes', []).extend(ssl_certs_lst)

        ## handle port mappings
        def pmap_fn(bcfg):
            if bcfg['proxy_mode'] == 'prefer_path' and bcfg['proxy_path']:
                return  ## skip noop

            ## either proxy_mode in ['both', 'prefer_port'] or proxy_path
            ## is empty, in any case, port is needed
            setdefault_none(tmpl_sets, 'ports', []).append(
              "{0}:{0}".format(bcfg['port'])
            )

        pmap_fn(pcfg['metrics'])
        pmap_fn(pcfg['s3_frontend'])

        if tmpl_sets:
            setdefault_none(setdefault_none(my_subcfg,
              'templates', {}), 'templates', {}
            ).update(rprxy_service_cfg_settings=tmpl_sets)

        return my_subcfg



class DockerCfgServiceCloudServerNormer(DockerCfgServiceNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'service_name',
          DefaultSetterConstant('zenko_cloudserver')
        )

        self._add_defaultsetter(kwargs, 'image',
          DefaultSetterConstant('zenko/cloudserver')
        )

        self._add_defaultsetter(kwargs, 'enabled',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'image_version',
          DefaultSetterConstant(None)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DockerCfgServiceCloudServerBuildNormer(pluginref),
          DockerCfgServiceCoudServerMetaDataPathNormer(pluginref),
        ]

        super(DockerCfgServiceCloudServerNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['services', 'cloudserver']


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        tmpl_sets = {
          'container_name': my_subcfg['container_name'],
          'image': my_subcfg['image'],
        }

        bsets = my_subcfg['build']

        if bsets['enabled']:
            if bsets['version_overwrite']:
                my_subcfg['image_version'] = \
                  bsets['version_overwrite']['version']

            tmpl_sets['image'] += '-selfbuild'
            tmpl_sets['build'] = bsets['settings']

            my_subcfg['is_building'] = True

        if my_subcfg['image_version']:
            tmpl_sets['image'] += ':{}'.format(my_subcfg['image_version'])

        ## handle s3 metadata path
        mdp = my_subcfg['s3_metadata_path']

        if mdp['container']:
            setdefault_none(tmpl_sets, 'environment', {}).update(
              S3METADATAPATH=mdp['container']
            )

        if mdp.get('host', False):
            setdefault_none(tmpl_sets, 'volumes', []).append(
              mdp['host'] + ':' + mdp['container']
            )

        if tmpl_sets:
            setdefault_none(setdefault_none(my_subcfg,
              'templates', {}), 'templates', {}
            ).update(cloudserver_service_settings=tmpl_sets)

        return my_subcfg



##
## note: zenko cloud server is still a very active project but
##   unfortunately they stopped publishing official docker releases a
##   couple years ago for some reason, the recommendation is because of
##   that to self-build image based on newer releases
##
class DockerCfgServiceCloudServerBuildNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'enabled',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'use_default_settings',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'default_settings',
          DefaultSetterConstant({
            'context': 'https://github.com/scality/cloudserver.git',
            'dockerfile': 'Dockerfile',
            'target': 'production',
          })
        )

        ## version might be different when building image one-self
        self._add_defaultsetter(kwargs, 'version_overwrite',
          DefaultSetterConstant(None)
        )

        self._add_defaultsetter(kwargs, 'settings',
          DefaultSetterConstant({})
        )

        super(DockerCfgServiceCloudServerBuildNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['build']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['enabled']:
            return my_subcfg

        settings = my_subcfg['settings']

        if my_subcfg['use_default_settings']:
            settings = merge_dicts(copy.deepcopy(
              my_subcfg['default_settings']
            ), settings)

            my_subcfg['settings'] = settings

        vo = my_subcfg['version_overwrite']

        if vo:
            if not isinstance(vo, collections.abc.Mapping):
                vo = { 'type': 'tag', 'version': vo }
                my_subcfg['version_overwrite'] = vo

            tmp = vo['version']

            if vo['type'] == 'tag':
                tmp = "refs/tags/" + tmp

            my_subcfg['settings']['context'] += "#{}".format(tmp)

        return my_subcfg



class DockerCfgServiceCoudServerMetaDataPathNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'container',
          DefaultSetterConstant('/usr/src/app/localMetadata')
        )

        super(DockerCfgServiceCoudServerMetaDataPathNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['s3_metadata_path']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        hp = my_subcfg.get('host', None)

        if hp:
            hpc = setdefault_none(my_subcfg, 'hostdir_config', {})
            hpc['path'] = hp

            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
            pcfg = pcfg['dirs']

            dmap = setdefault_none(pcfg, '_local', {})
            dmap[hp] = hpc

        return my_subcfg



class CfgFilesPassesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          CfgFilePassConfigNormer(pluginref),
          CfgFilePassAuthConfNormer(pluginref),
          CfgFilePassLocConfigNormer(pluginref),
          CfgFileRevProxyNormer(pluginref),
        ]

        super(CfgFilesPassesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['cfgfiles']


class CfgFilePassXNormerBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        if self.allow_custom_extras_settings:
            self._add_defaultsetter(kwargs,
              'allow_custom_extras_settings', DefaultSetterConstant(
                 self.allow_custom_extras_settings
              )
            )

        super(CfgFilePassXNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def allow_custom_extras_settings(self):
        return True

    @property
    def my_docker_service(self):
        return 'cloudserver'

    def _check_empty(self, cfg, my_subcfg, cfgpath_abs):
        return not bool(my_subcfg['settings'])

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['config_id'] = cfgpath_abs[-1]

        ## complete srcfile template path when necessary, relative
        ## paths are always relative to current role path
        sf_tmpl = my_subcfg.get('srcfile_template', None)

        if sf_tmpl:
            if sf_tmpl[0] != '/':
                sf_tmpl = self.pluginref.get_ansible_var('role_path') \
                        + '/' + sf_tmpl

                my_subcfg['srcfile_template'] = sf_tmpl

        ## complete target path if necessary, relatives path are
        ## always relative to compose root dir
        tp = my_subcfg['target_path']

        if tp[0] != '/':
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
            tp = pcfg['docker']['dirs']['compose_root']['path'] + '/' + tp
            my_subcfg['target_path'] = tp

        fc = setdefault_none(my_subcfg, 'file_config', {})
        fc['dest'] = tp

        ##
        ## note: at least some of these files can contain login secrets
        ##   (authdata), so access should be very restricted on default
        ##
        setdefault_none(fc, 'mode', '600')
        return my_subcfg


    def _mod_my_dockservice_template(self, cfg,
        my_subcfg, cfgpath_abs, template
    ):
        return template


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['enabled'] = True

        if self._check_empty(cfg, my_subcfg, cfgpath_abs):
            ## dont template empty config file
            my_subcfg['enabled'] = False
            return my_subcfg

        if self.allow_custom_extras_settings:
            if my_subcfg['allow_custom_extras_settings']:
                 ## optionally add custom extra settings which we assume
                 ## are not currently supported by application but also
                 ## do not produce errors (are basically ignored) to
                 ## settings which are exported to config file
                 for k, v in my_subcfg['custom_extra_settings'].items():
                     if k in my_subcfg['settings']:
                         continue

                     my_subcfg['settings'][k] = v

        ## handle volume mounting for config files
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        pcfg = pcfg['docker']['services'][self.my_docker_service]

        my_subcfg['enabled'] = pcfg['enabled']

        if pcfg['enabled']:
            pcfg = pcfg['templates']['templates']

            pcfg["config_file_settings_{}".format(cfgpath_abs[-1])] = \
              self._mod_my_dockservice_template(cfg, my_subcfg, cfgpath_abs,
                {
                  'volumes': [my_subcfg['target_path'] \
                     + ':' + my_subcfg['target_path_docker'] + ':ro'
                  ],
                }
              )

        return my_subcfg



class RevProxySnippetInstNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'enabled',
          DefaultSetterConstant(True)
        )

        super(RevProxySnippetInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['snippets', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'source_template'


class RevProxyDefSnippetsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RevProxyDefSnippetForceHttpsNormer(pluginref),
          RevProxyDefSnippetProxyPathDefaultsNormer(pluginref),
          RevProxyDefSnippetGlobalDefsNormer(pluginref),
          RevProxyDefSnippetDataPathNormer(pluginref),
          RevProxyDefSnippetMetricsPathNormer(pluginref),
        ]

        super(RevProxyDefSnippetsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['default_snippets']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        rp = self.pluginref.get_ansible_var('role_path')
        setdefault_none(my_subcfg, 'snippets_root_path', rp)
        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        if pcfg['no_default_snippets']:
            return my_subcfg

        # add all defined default snippets to snippets
        for k, v in my_subcfg['snippets'].items():
            if not v['enabled']:
                ## skip disabled default snippets
                continue

            pcfg['snippets'][k] = v

        return my_subcfg


class RevProxyDefSnippetNormerBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'enabled',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'source_template',
          DefaultSetterConstant(self.source_template)
        )

        super(RevProxyDefSnippetNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    @abc.abstractmethod
    def source_template(self):
        pass

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        tmp = my_subcfg['source_template']

        if tmp[0] != '/':
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
            tmp = pcfg['snippets_root_path'] + '/' + tmp
            my_subcfg['source_template'] = tmp

        return my_subcfg


class RevProxyDefSnippetForceHttpsNormer(RevProxyDefSnippetNormerBase):

    @property
    def source_template(self):
        return 'templates/config/rproxy/snippets/force_https.j2'

    @property
    def config_path(self):
        return ['snippets', 'force_https']


class RevProxyDefSnippetMetricsPathNormer(RevProxyDefSnippetNormerBase):

    @property
    def source_template(self):
        return 'templates/config/rproxy/snippets/metrics_path.j2'

    @property
    def config_path(self):
        return ['snippets', 'metrics_path']


class RevProxyDefSnippetProxyPathDefaultsNormer(RevProxyDefSnippetNormerBase):

    @property
    def source_template(self):
        return 'templates/config/rproxy/snippets/proxypath_defaults.j2'

    @property
    def config_path(self):
        return ['snippets', 'proxypath_defaults']


class RevProxyDefSnippetDataPathNormer(RevProxyDefSnippetNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'timeouts',
          DefaultSetterConstant({})
        )

        super(RevProxyDefSnippetDataPathNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def source_template(self):
        return 'templates/config/rproxy/snippets/datapath.j2'

    @property
    def config_path(self):
        return ['snippets', 'data_path']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        my_subcfg['client_body_maxsize'] = \
          pcfg['global_defaults_http']['client_body_maxsize']

        tos = my_subcfg['timeouts']

        setdefault_none(tos, 'proxy_connect', '10s')
        setdefault_none(tos, 'proxy_read', '1h')
        setdefault_none(tos, 'proxy_send', '1h')
        setdefault_none(tos, 'send', '1h')

        return my_subcfg


class RevProxyDefSnippetGlobalDefsNormer(RevProxyDefSnippetNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'disable_logging',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'client_body_maxsize',
          DefaultSetterConstant('0')
        )

        super(RevProxyDefSnippetGlobalDefsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def source_template(self):
        return 'templates/config/rproxy/snippets/global_defaults_http.j2'

    @property
    def config_path(self):
        return ['snippets', 'global_defaults_http']



class CfgFileRevProxyNormer(CfgFilePassXNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'srcfile_template',
          DefaultSetterConstant('templates/config/rproxy/nginx.conf.j2')
        )

        self._add_defaultsetter(kwargs, 'target_path',
          DefaultSetterConstant('config/nginx/nginx.conf')
        )

        self._add_defaultsetter(kwargs, 'target_path_docker',
          DefaultSetterConstant('/etc/nginx/nginx.conf')
        )

        self._add_defaultsetter(kwargs, 'force_https',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'no_default_snippets',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'snippets',
          DefaultSetterConstant({})
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RevProxyDefSnippetsNormer(pluginref),
          RevProxySnippetInstNormer(pluginref),
        ]

        super(CfgFileRevProxyNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['reverse_proxy']

    @property
    def allow_custom_extras_settings(self):
        return False

    @property
    def my_docker_service(self):
        return 'reverse_proxy'

    def _check_empty(self, cfg, my_subcfg, cfgpath_abs):
        return False

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg = super()._handle_specifics_presub(
           cfg, my_subcfg, cfgpath_abs
        )

        templ_cfg = merge_dicts(copy.deepcopy(my_subcfg['file_config']),
          setdefault_none(my_subcfg, 'template_config', {})
        )

        templ_cfg['dest'] = my_subcfg['file_config']['dest']
        templ_cfg['src'] = my_subcfg['srcfile_template']

        my_subcfg['template_config'] = templ_cfg

        ## check if we have at least one user which should
        ## not be allowed to create buckets, if so ensure
        ## appropriate nginx config code is generated to
        ## enforce this
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        bucket_create_okay = {}
        bucket_create_forbidden = {}

        for k, v in pcfg['users']['users'].items():
            if v['permissions']['bucket_create']:
                bucket_create_okay[k] = v
            else:
                bucket_create_forbidden[k] = v

        if bucket_create_forbidden:
            my_subcfg['_user_perm_handling'] = {}
            my_subcfg['_user_perm_handling']['bcreate_restrict'] = {
              'allow_users': list(bucket_create_okay.values()),
            }

        return my_subcfg


    def _mod_my_dockservice_template(self, cfg,
        my_subcfg, cfgpath_abs, template
    ):
        setdefault_none(template, 'ports', []).append('80:80')
        return template

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg = super()._handle_specifics_postsub(
           cfg, my_subcfg, cfgpath_abs
        )

        if not my_subcfg['enabled']:
            return my_subcfg

        forwards = {}

        servers_cfg = {'default': {'listen_sfx': []},
           'metrics': {'listen_sfx': []}, 's3api': {'listen_sfx': []}
        }

        my_subcfg['_servers'] = servers_cfg

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        tmp = pcfg.get('ssl_certs', None)

        if tmp:
            my_subcfg['ssl_certs'] = tmp

            for x in servers_cfg.values():
                x['listen_sfx'].append('ssl')

        for x in servers_cfg.values():
            x['listen_sfx'] = ' '.join(x['listen_sfx'])

            if x['listen_sfx']:
                x['listen_sfx'] = ' ' + x['listen_sfx']

        def generate_fwd_settings(bcfg, fwd_key):
            tmp = bcfg['port']

            fwd_cfg = {'backend': {'server': "{}:{}".format(
                pcfg['docker']['services']['cloudserver']['container_name'],
                tmp
              )
            }}

            forwards[fwd_key] = fwd_cfg

            do_path = bcfg['proxy_mode'] == 'prefer_path' \
                    and bcfg['proxy_path']

            do_both = bcfg['proxy_mode'] == 'both'

            if do_path or do_both:
                fwd_cfg['path'] = bcfg['proxy_path']

            if bcfg['proxy_mode'] == 'prefer_port' or do_both:
                fwd_cfg['port'] = tmp

        generate_fwd_settings(pcfg['s3_frontend'], 's3api')
        generate_fwd_settings(pcfg['metrics'], 'metrics')

        my_subcfg['_forwards'] = forwards

        return my_subcfg



class CfgFilePassAuthConfNormer(CfgFilePassXNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'srcfile_template',
          DefaultSetterConstant(None)
        )

        self._add_defaultsetter(kwargs, 'target_path',
          DefaultSetterConstant('config/zenko/auth_config.json')
        )

        self._add_defaultsetter(kwargs, 'target_path_docker',
          DefaultSetterConstant('/usr/src/app/conf/authdata.json')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ## strictly parsed, no custom extras possible
          ##CfgFilePassConfigSettingsCustomExtraNormer(pluginref),
          CfgFilePassConfigSettingsNormer(pluginref),
        ]

        super(CfgFilePassAuthConfNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['auth_config']

    @property
    def allow_custom_extras_settings(self):
        return False



class CfgFilePassConfigNormer(CfgFilePassXNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'srcfile_template',
          DefaultSetterConstant('templates/config/zenko/config.json.j2')
        )

        self._add_defaultsetter(kwargs, 'target_path',
          DefaultSetterConstant('config/zenko/config.json')
        )

        self._add_defaultsetter(kwargs, 'target_path_docker',
          DefaultSetterConstant('/usr/src/app/config.json')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          CfgFilePassConfigSettingsCustomExtraNormer(pluginref),
          CfgFilePassConfigUpstreamBaseNormer(pluginref),
          CfgFilePassConfigSettingsNormer(pluginref),
        ]

        super(CfgFilePassConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['config']



class CfgFilePassConfigUpstreamBaseNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'enabled',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'docker_source_path',
          ##DefaultSetterConstant('/usr/src/app/config.json')
          DefaultSetterConstant('')
        )

        ##
        ## note: we use jsdelivr here instead of a direct github link,
        ##   not so much because of all its extra goodies but mainly
        ##   to always point to the latest head stand of this file
        ##   without knowing what the corresponding current branch name is
        ##
        self._add_defaultsetter(kwargs, 'src_url',
          DefaultSetterConstant(
            'https://cdn.jsdelivr.net/gh/scality/cloudserver/config.json'
          )
        )

        self._add_defaultsetter(kwargs, 'disable_all_optional_defaults',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'default_rest_endpoints',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'default_web_endpoints',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'default_replication_endpoints',
          DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs, 'default_external_backends',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'default_bucket_notify_dests',
          DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs, 'default_health_check_settings',
          DefaultSetterConstant(True)
        )

        super(CfgFilePassConfigUpstreamBaseNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['upstream_base']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['enabled']:
            return my_subcfg

        ## note: zenko does not work with an empty config, so it
        ##   makes sense in general to start with the upstream
        ##   default config, but some parts of it makes no sense
        ##   most of the time like its predefined default rest
        ##   and web endpoints
        merge_overwrites = {}
        export_configs = {}

        disable_all = my_subcfg['disable_all_optional_defaults']

        if my_subcfg['docker_source_path']:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

            export_configs['get_cfg_from_docker'] = {
              'name': "tmp_get_cfg_from_docker",
              'image': pcfg['docker']['services']['cloudserver']['image'],
              'command': ['sh', '-c', "cat '{}'".format(
                 my_subcfg['docker_source_path']
              )],
              'pull': 'always',
              'detach': False,
              'cleanup': True,
            }

            ansible_assert(not my_subcfg['src_url'],
               "use either upstream_base from docker image"\
               " ('docker_source_path' key) or from direct download url"\
               " ('src_url' key) but not both together"
            )

        if my_subcfg['src_url']:
            if 'cdn.jsdelivr.net' in my_subcfg['src_url']:
                ## using jsdelivr cdn network, ensure that download link
                ## points to absolute latest upstream version by forcing
                ## a cdn cache clear
                clear_url = my_subcfg['src_url'].replace('//cdn.', '//purge.')

                self.pluginref.exec_module('ansible.builtin.uri',
                   modargs={'url': clear_url}
                )

            tmp = self.pluginref.exec_module('ansible.builtin.uri',
               modargs={'url': my_subcfg['src_url'], 'return_content': True}
            )

            ## download config and parse as json and combine with overwrites
            merge_overwrites = json.loads(tmp['content'])

        if disable_all or not my_subcfg['default_rest_endpoints']:
            my_subcfg['default_rest_endpoints'] = False
            merge_overwrites['restEndpoints'] = {}

        if disable_all or not my_subcfg['default_web_endpoints']:
            my_subcfg['default_web_endpoints'] = False
            merge_overwrites['websiteEndpoints'] = []

        if disable_all or not my_subcfg['default_replication_endpoints']:
            my_subcfg['default_replication_endpoints'] = False
            merge_overwrites['replicationEndpoints'] = []

        if disable_all or not my_subcfg['default_external_backends']:
            my_subcfg['default_external_backends'] = False
            merge_overwrites['externalBackends'] = {}

        if disable_all or not my_subcfg['default_bucket_notify_dests']:
            my_subcfg['default_bucket_notify_dests'] = False
            merge_overwrites['bucketNotificationDestinations'] = []

        if disable_all or not my_subcfg['default_health_check_settings']:
            my_subcfg['default_health_check_settings'] = False
            merge_overwrites['healthChecks'] = {}

        my_subcfg['merge_overwrites'] = merge_overwrites

        if export_configs:
            my_subcfg['_export_configs'] = export_configs

        return my_subcfg



class CfgFilePassLocConfigNormer(CfgFilePassXNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, 'srcfile_template',
          DefaultSetterConstant('templates/config/zenko/loc_config.json.j2')
        )

        self._add_defaultsetter(kwargs, 'target_path',
          DefaultSetterConstant('config/zenko/loc_config.json')
        )

        self._add_defaultsetter(kwargs, 'target_path_docker',
          DefaultSetterConstant('/usr/src/app/locationConfig.json')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ##
          ## note: loc config is very strictly parsed,
          ##   no custom extra stuff possible
          ##
          ##CfgFilePassLocConfigSettingsCustomExtraNormer(pluginref),
          CfgFilePassLocConfigSettingsNormer(pluginref),
        ]

        super(CfgFilePassLocConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def allow_custom_extras_settings(self):
        return False

    @property
    def config_path(self):
        return ['location_config']


class CfgFilePassXSettNormerExtraBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs, '_cfgheader_comment',
          DefaultSetterConstant(
            "!!IMPORTANT: this file is auto-generated by"\
            " ansible, do not change it manually!!"
          )
        )

        super(CfgFilePassXSettNormerExtraBase, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['custom_extra_settings']


class CfgFilePassConfigSettingsNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['settings']

class CfgFilePassLocConfigSettingsNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['settings']

class CfgFilePassConfigSettingsCustomExtraNormer(CfgFilePassXSettNormerExtraBase):
    pass

##class CfgFilePassLocConfigSettingsCustomExtraNormer(CfgFilePassXSettNormerExtraBase):
##    pass



class S3FrontendNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'port', DefaultSetterConstant(8000)
        )

        self._add_defaultsetter(kwargs,
          ## optional subpath to make this avaible on in reverse-proxy mode
          'proxy_path', DefaultSetterConstant('/')
        )

        self._add_defaultsetter(kwargs,
          'proxy_mode', DefaultSetterConstant('prefer_path')
          ##'proxy_mode', DefaultSetterConstant('both')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RestEndpointsRootNormer(pluginref),
          S3BucketsTopNormer(pluginref),
        ]

        super(S3FrontendNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['s3_frontend']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## forward defined s3 port to config file
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        for x in ['cfgfiles', 'config', 'settings']:
            pcfg = setdefault_none(pcfg, x, {})

        pcfg['port'] = my_subcfg['port']

        ## also ensure port is mapped docker-wise when necessary
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        pcfg = pcfg['docker']['services']

        if not pcfg['reverse_proxy']['enabled']:
            pcfg = pcfg['cloudserver']['templates']['templates']

            pcfg['s3_frontend_settings'] = {
              'ports': ["{0}:{0}".format(my_subcfg['port'])]
            }

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        conn = pcfg.get('connection', {})

        if conn.get('url', None):
            ## create metrics url when connection is defined
            murl = ""

            if conn['scheme']:
                murl = conn['scheme'] + '://'

            murl += conn['host']

            has_path = bool(my_subcfg['proxy_path'])
            use_path = my_subcfg['proxy_mode'] in ['prefer_path', 'both']

            if has_path and use_path:
                if my_subcfg['proxy_path'] != '/':
                    murl += my_subcfg['proxy_path']
            else:
                ## use metrics port
                murl += ':' + str(my_subcfg['port'])

            conn['s3api_url'] = murl

        return my_subcfg



class RestEndpointsRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'auto_default', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DefaultEndpointsNormer(pluginref),
          RestEndpointInstNormer(pluginref),
        ]

        super(RestEndpointsRootNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['rest_endpoints']



class DefaultEndpointsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'disable_all', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DefaultEndpointLocalHostNormer(pluginref),
          DefaultEndpointDockerServiceNormer(pluginref),
          DefaultEndpointHostNameNormer(pluginref),
          DefaultEndpointConnectionS3ApiUrlNormer(pluginref),
        ]

        super(DefaultEndpointsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['default_endpoints']



class RestEndpointInstBaseNormer(NormalizerNamed):

    def _add_endpoint_cfgfile_entry(self, re_update, pa_root,
        cfg, my_subcfg, cfgpath_abs
    ):
        if not isinstance(pa_root, collections.abc.Mapping):
            ## assume int distance to root level
            pa_root = self.get_parentcfg(cfg, cfgpath_abs, level=pa_root)

        pcfg = pa_root

        tmp = ['cfgfiles', 'config', 'settings', 'restEndpoints']

        for x in tmp:
            pcfg = setdefault_none(pcfg, x, {})

        pcfg.update(re_update)


    def _handle_backend(self, rlvl, cfg, my_subcfg, cfgpath_abs):
        pa_root = self.get_parentcfg(cfg, cfgpath_abs, level=rlvl)
        back_cfg = pa_root['storage_backends']

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=(rlvl - 2))

        ba = my_subcfg.get('backend', None)

        errbase = "bad config for frontend rest endpoint '{}'".format(
          '.'.join(cfgpath_abs)
        )

        if ba:
            ## directly attach backend config here,
            ## error out if backend cannot be found
            ba_cfg = back_cfg['backends_by_name'].get(ba, None)

            ansible_assert(ba_cfg,
              "{}, no backend known with given name '{}', must"\
              " be one of these:\n{}".format(errbase, ba,
                 list(back_cfg['backends_by_name'].keys())
              )
            )

        else:
            ## fallback to default backend if possible, otherwise error out
            ansible_assert(pcfg['auto_default'],
               "{}, no explicit backend mapping given, either specify one"\
               " or set '{}' to true to default auto connect frontend"\
               " endpoints to default backend".format(errbase,
                  '.'.join(cfgpath_abs[:-2] + ['auto_default'])
               )
            )

            defback = back_cfg.get('default_backend', None)

            ansible_assert(defback,
               "{}, unable to auto default rest endpoint to backend, there"\
               " seems to be no default backend defined, ensure one"\
               " backend is marked as default or always set an explicit"\
               " backend mapping for each frontend rest endpoint".format(
                   errbase
               )
            )

            ba = defback

        my_subcfg['backend'] = ba



class DefaultEndpointConnectionS3ApiUrlNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['connection_s3api']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'enabled', not pcfg['disable_all'])

        if not my_subcfg['enabled']:
            return my_subcfg

        rcfg = self.get_parentcfg(cfg, cfgpath_abs, level=5)

        s3api_url = (rcfg.get('connection', None) or {}).get(
          's3api_url', None
        )

        if not s3api_url:
            display.vv(
               "[INFO(default_endpoints.connection_s3api)]:"\
               " connection.s3api_url seems not to be set,"\
               " skip this default endpoint"
            )

            return my_subcfg

        display.vv(
           "[INFO(default_endpoints.connection_s3api)]: found"\
           " connection.s3api_url, will create default endpoint from it"
        )

        s3api_url = urlparse(s3api_url)

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        eps = setdefault_none(pcfg, 'endpoints', {})
        setdefault_none(eps, s3api_url.hostname, None)

        return my_subcfg



class DefaultEndpointDockerServiceNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['docker_service']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'enabled', not pcfg['disable_all'])

        if not my_subcfg['enabled']:
            return my_subcfg

        rcfg = self.get_parentcfg(cfg, cfgpath_abs, level=5)

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        eps = setdefault_none(pcfg, 'endpoints', {})
        setdefault_none(eps,
          rcfg['docker']['services']['cloudserver']['container_name'], None
        )

        return my_subcfg



class DefaultEndpointHostNameNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'short', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'fqdn', DefaultSetterConstant(True)
        )

        super(DefaultEndpointHostNameNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['hostname']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'enabled', not pcfg['disable_all'])

        if not my_subcfg['enabled']:
            return my_subcfg

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        eps = setdefault_none(pcfg, 'endpoints', {})

        if my_subcfg['short']:
            setdefault_none(eps,
              self.pluginref.get_ansible_var('ansible_hostname'), None
            )

        if my_subcfg['fqdn']:
            setdefault_none(eps,
              self.pluginref.get_ansible_var('ansible_fqdn'), None
            )

        return my_subcfg



class DefaultEndpointLocalHostNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hostname', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'ip', DefaultSetterConstant(True)
        )

        super(DefaultEndpointLocalHostNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['localhost']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'enabled', not pcfg['disable_all'])

        if not my_subcfg['enabled']:
            return my_subcfg

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        eps = setdefault_none(pcfg, 'endpoints', {})

        if my_subcfg['hostname']:
            setdefault_none(eps, 'localhost', None)

        if my_subcfg['ip']:
            setdefault_none(eps, '127.0.0.1', None)

        return my_subcfg



class RestEndpointInstNormer(RestEndpointInstBaseNormer):

    @property
    def config_path(self):
        return ['endpoints', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'backend'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        self._handle_backend(4, cfg, my_subcfg, cfgpath_abs)

        ## create config entry for rest endpoint(s)
        self._add_endpoint_cfgfile_entry({
            my_subcfg['name']: my_subcfg['backend']['name'],
          }, 4, cfg, my_subcfg, cfgpath_abs
        )

        return my_subcfg



class S3BucketsTopNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'force_delete', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          S3BucketInstNormer(pluginref),
        ]

        super(S3BucketsTopNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['buckets']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        excl = my_subcfg['exclusive']

        if excl:
            excl_orig = excl

            if excl == True:
                excl = 'owners'
                my_subcfg['exclusive'] =  excl

            ## get configured buckets and corresponding owners
            usr_map = {}

            for k, v in my_subcfg['buckets'].items():
                cred_map = v['owner']['credentials']['key_sets']
                creds_key = next(iter(cred_map.keys()))
                creds = cred_map[creds_key]
                creds['kset_mapkey'] = creds_key

                ## create one cfg element per user
                usr = v['owner']['name']
                usr_map.setdefault(usr, {
                  ## config to later read all defined buckets for user
                  'get_buckets_cfg': {
                     ##
                     ## note: in principle one user can have multiple
                     ##   valid access/secret key pairs at the same time
                     ##   and different ones might be used to
                     ##   manage/create the bucket, but ultimately they
                     ##   all fallback to the same user and it really
                     ##   doesn't matter such much which pair you use
                     ##   for access
                     ##
                     'access_key': creds['access_key'],
                     'secret_key': creds.get('secret_key', None),
                  },
                  'delete_bad_buckets_cfg': {
                     'access_key': creds['access_key'],
                     'secret_key': creds.get('secret_key', None),
                     'state': 'absent',
                     'force': my_subcfg['force_delete'],
                  },
                  ## mapping listing all buckets which should exist
                  'okay_buckets': {},
                  'user': usr, 'credential': creds,
                }).get('okay_buckets').update({v['name']: True})

            if excl == 'all_users':
                ## in all_users case additionally check users
                ##   which dont have any buckets defined as owners
                pa_root = self.get_parentcfg(cfg, cfgpath_abs, level=2)

                for k, v in pa_root['users']['users'].items():
                    cred_map = v['credentials']['key_sets']
                    creds_key = next(iter(cred_map.keys()))
                    creds = cred_map[creds_key]
                    creds['kset_mapkey'] = creds_key

                    ## note: any user got new here will obviously have
                    ##   no buckets as owner defined by config, meaning
                    ##   all its existing buckets will be deleted
                    usr = v['name']
                    usr_map.setdefault(usr, {
                      'get_buckets_cfg': {
                         'access_key': creds['access_key'],
                         'secret_key': creds.get('secret_key', None),
                      },
                      'delete_bad_buckets_cfg': {
                         'access_key': creds['access_key'],
                         'secret_key': creds.get('secret_key', None),
                         'state': 'absent',
                         'force': my_subcfg['force_delete'],
                      },
                      'okay_buckets': {},
                      'user': usr, 'credential': creds,
                    })

            else:
                ansible_assert(excl == 'owners',
                  "invalid exclusive setting '{}', must be one of"\
                  " these:\n{}".format(excl_orig,
                     [True, False, 'owners', 'all_users']
                  )
                )

            setdefault_none(my_subcfg, '_export_cfgs', {}).update(
              excludes=list(usr_map.values())
            )

        return my_subcfg



class S3BucketInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'use_default_auth', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          BucketPolicyNormer(pluginref),
          (BucketAclGrantHeadersNormer, True),
        ]

        super(S3BucketInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['buckets', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pa_root = self.get_parentcfg(cfg, cfgpath_abs, level=4)
        usr_cfg_root = pa_root['users']

        my_subcfg['name'] = norm_name_s3(my_subcfg['name'])

        ## handle owner user ref
        owner = my_subcfg.get('owner', None)

        if owner:
            if not isinstance(owner, collections.abc.Mapping):
                ## assume simple string
                my_own = owner.split('.')

                ansible_assert(len(my_own) < 3,
                   "bad s3 bucket subconfig, bucket definition '{}'"\
                   " given owner user string short form '{}' is ambigious"\
                   " as it contains more than one '.', please use the"\
                   " explicit submap format instead here".format(
                      '.'.join(cfgpath_abs), owner
                   )
                )

                owner = {'user': my_own[0]}

                if len(my_own) > 1:
                    owner['keyset_index'] = my_own[1]

            my_own = usr_cfg_root['users_by_name'].get(owner['user'], None)

            ansible_assert(my_own,
               "bad s3 bucket subconfig, bucket definition '{}' given"\
               " owner user '{}' does not exist".format(
                  '.'.join(cfgpath_abs), owner['user']
               )
            )

            setdefault_none(owner, 'keyset_index', 0)

            if my_own['bucket_admin'] and str(owner['keyset_index']) == "0":
                my_subcfg['use_default_auth'] = True

            else:

                try:
                    ## on default expect valid keyset array index
                    tmp = int(owner['keyset_index'])
                    my_subcfg['bucket_creds'] = my_own['config']['keys'][tmp]

                except ValueError:
                    ## if not integer expect valid access_key
                    tmp = None
                    user_akeys = []

                    for x in my_own['config']['keys']:
                        user_akeys.append(x['access'])

                        if x['access'] == owner['keyset_index']:
                            tmp = x
                            break

                    ansible_assert(tmp,
                       "bad s3 bucket subconfig, bucket definition '{}'"\
                       " given owner user '{}' does not have any access"\
                       " key '{}', must be one of these: {}".format(
                          '.'.join(cfgpath_abs), owner['user'],
                          owner['keyset_index'], user_akeys
                       )
                    )

                    my_subcfg['bucket_creds'] = tmp

                except IndexError:
                    ansible_assert(False,
                       "bad s3 bucket subconfig, bucket definition '{}'"\
                       " given owner user '{}' keyset index '{}' is invalid"\
                       " as it must be >= 0 and < {}".format(
                          '.'.join(cfgpath_abs), owner['user'], tmp,
                          len(my_own['config']['keys'])
                       )
                    )

            owner = my_own

        else:
            ## default unset owner to bucket-admin if bucket admin is defined
            ba = usr_cfg_root['bucket_admin']

            ansible_assert(ba,
              "bad s3 bucket subconfig, bucket definition '{}' has no"\
              " owner set which is only allowed if one user is marked as"\
              " bucket_admin, so either do that or specify an explicit"\
              " owner for this bucket".format('.'.join(cfgpath_abs))
            )

            owner = ba
            my_subcfg['use_default_auth'] = True

        my_subcfg['owner'] = owner

        ## handle region / backend-ref  (optional)
        ba_ref = my_subcfg.get('backend_ref', None)
        region = my_subcfg.get('region', None)

        ansible_assert(not ba_ref or not region,
           "bad s3 bucket subconfig, bucket definition '{}' either set"\
           " 'backend_ref' subkey or 'region', but never both at the"\
           " same time".format('.'.join(cfgpath_abs))
        )

        if ba_ref:
            ba_ref_tmp = ba_ref.split('.')

            try:
                ba_ref = pa_root['storage_backends']['backends'][
                  ba_ref_tmp[0]
                ][ba_ref_tmp[1]]

            except KeyError:
                ansible_assert(False,
                   "bad s3 bucket subconfig, bucket definition '{}',"\
                   " invalid backend_ref setting, no backend found matching"\
                   " this definition '{}'".format(
                      '.'.join(cfgpath_abs), ba_ref
                   )
                )

            my_subcfg['backend_ref'] = ba_ref
            region = ba_ref['name']
            my_subcfg['region'] = region

        ## handle other user access  (optional)
        acc = my_subcfg.get('access', None) or {}

        if acc:
            bpol = setdefault_none(my_subcfg, 'bucket_policy', {})
            bpol = setdefault_none(bpol, 'statements', {})

            def get_pol_users(utype, usrmap):
                res = []

                for k, v in usrmap.items():
                    ucfg = usr_cfg_root['users_by_name'].get(k, None)

                    ansible_assert(ucfg,
                       "bad s3 bucket subconfig, bucket definition '{}',"\
                       " referenced '{}' policy user '{}' does not"\
                       " exist".format('.'.join(cfgpath_abs), utype,k)
                    )

                    res.append(ucfg['config']['arn'])

                if len(res) == 1:
                    return res[0]

                return res

            pol_res_bucket = "arn:aws:s3:::{}".format(my_subcfg['name'])
            pol_res_items_all = "arn:aws:s3:::{}/*".format(my_subcfg['name'])

            polbase_tmplates = {
              'bucket_list': {
                 "Sid": "Allow-Bucket-Listing",
                 "Effect": "Allow",
                 "Action": "s3:ListBucket",
                 "Resource": pol_res_bucket,
              },
              'read_all_objects': {
                 "Sid": "Allow-Read-All-Objects",
                 "Effect": "Allow",
                 "Action": "s3:GetObject",
                 "Resource": pol_res_items_all,
              },
              'write_all_objects': {
                 "Sid": "Allow-Write-All-Objects",
                 "Effect": "Allow",
                 "Action": "s3:PutObject",
                 "Resource": pol_res_items_all,
              },
              'delete_all_objects': {
                 "Sid": "Allow-Delete-All-Objects",
                 "Effect": "Allow",
                 "Action": "s3:DeleteObject",
                 "Resource": pol_res_items_all,
              },
              'object_tagging_all': {
                 "Sid": "Allow-Tagging-All-Objects",
                 "Effect": "Allow",
                 "Action": [
                    "s3:GetObjectTagging",
                    "s3:PutObjectTagging",
                    "s3:DeleteObjectTagging",
                 ],
                 "Resource": pol_res_items_all,
              },
              'full_bucket_access': {
                 "Sid": "Allow-Full-Bucket-Access",
                 "Effect": "Allow",
                 "Action": "s3:*",
                 "Resource": [pol_res_bucket, pol_res_items_all],
              },
            }

            ##
            ## note: in modern standard aws s3 policies have fully
            ##   replaced acl stuff and deprecated acl stuff is
            ##   not used anymore for new buckets, unfortunately
            ##   in zenko policy support is currently still
            ##   somewhat patchy and sometimes buggy and acl's
            ##   are still around everywhere and sometimes necessary,
            ##   so we do atm a mix of policy and acl's here
            ##
            acl_grants = setdefault_none(
              setdefault_none(
                setdefault_none(my_subcfg, 'acl', {}),
                  'grant_headers', {}
              ), 'grantees', {})

            for k, v in acc.items():
                pol_lst = []

                ##
                ## note: actually reading / writing and so of
                ##   objects works totally fine with policies, but for
                ##   some special scenarios one still needs additional
                ##   authorisation by bucket acl, like:
                ##
                ##     -> getting an expected 404 ("key does not exist")
                ##        instead of 403 ("no permissions") when
                ##        querying non existant keys
                ##
                acl_grant_type = 'read'

                if k == 'read_only':
                    pol_lst = ['bucket_list', 'read_all_objects']
                elif k == 'read_write':
                    pol_lst = ['bucket_list', 'read_all_objects',
                      'write_all_objects'
                    ]
                elif k == 'data_owner':
                    ## a data owner can do anything with
                    ## stored objects, read, write and delete
                    pol_lst = ['bucket_list', 'read_all_objects',
                      'write_all_objects', 'delete_all_objects'
                    ]
                elif k == 'sonatype_nexus':
                    ## for sonatype nexus s3 blobstore backends,
                    ## in principle a data_owner, but need a lot
                    ## of additional more obscure permissions
                    pol_lst = ['bucket_list', 'read_all_objects',
                      'write_all_objects', 'delete_all_objects',
                      'object_tagging_all', {
                         "Sid": "Sonatype-Nexus-Blobstore-Extras",
                         "Effect": "Allow",
                         "Action": [
                            "s3:GetBucketPolicy"
                         ],
                         "Resource": [pol_res_bucket],
                      },
                    ]
                elif k == 'write_only':
                    pol_lst = ['write_all_objects']
                elif k == 'full':
                    pol_lst = ['full_bucket_access']
                    acl_grant_type = 'full'
                else:
                    ansible_assert(False,
                       "bad s3 bucket subconfig, bucket definition '{}',"\
                       " unsupported policy access type '{}', must be one"\
                       " of these: {}".format('.'.join(cfgpath_abs), k, [
                            'read_only', 'read_write', 'data_owner',
                            'write_only', 'full'
                          ]
                       )
                    )

                pusers = get_pol_users(k, v)
                setdefault_none(acl_grants, acl_grant_type, {}).update(v)

                for x in pol_lst:
                    if not isinstance(x, collections.abc.Mapping):
                        x = polbase_tmplates[x]

                    pstat = copy.deepcopy(x)
                    pstat['Principal'] = {
                      ##'CanonicalUser': pusers,
                      'AWS': pusers,
                    }

                    pol_id = "_cfg_{}_{}".format(k, pstat['Sid'])
                    bpol[pol_id] = pstat

        ## create export module configs
        c = setdefault_none(my_subcfg, 'configs', {})
        c = setdefault_none(c, 'bucket_manage', {})

        c.update({
          'name': my_subcfg['name'],
          'state': my_subcfg['state'],
        })

        if region:
            c['region'] = region

        ##
        ## note: this seems to be the modern amazon s3 default
        ##   for newly created buckets, but not so in zenko it
        ##   seems, so we enforce it here
        ##
        ## update: unfortunately zenko does not support the
        ##   object_ownership model of aws so far :(
        ##
        ##setdefault_none(c, 'object_ownership', 'BucketOwnerEnforced')

        if not c.get('public_access', False):
            setdefault_none(c, 'delete_public_access', True)

        if not my_subcfg['use_default_auth']:
            setdefault_none(c, 'access_key',
              my_subcfg['bucket_creds']['access']
            )

            skey = my_subcfg['bucket_creds'].get('secret', None)

            if skey:
                setdefault_none(c, 'secret_key', skey)

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['configs']['bucket_manage']

        bpol = my_subcfg['bucket_policy']['_export_formats']['map']
        if bpol:
            c['policy'] = bpol

        return my_subcfg



##
## note: in principle there are 3 ways to define an ACL:
##
##   1. "canned acl": one string word with "x-amz-acl"
##         header to select a special predefined
##         scenario (private, public-read, ...), this
##         one is better handled directly by upstream
##         aws module ("<bucket>.configs.bucket_manage")
##         and therefore not supported here
##
##   2. simplified format with "grant-xxx" header,
##      this is handled by this class
##
##   3. full explicit xml based acl format, this is
##      currently very buggy and seemingly unworking
##      for zenko, so we dont use it atm
##
## see also:
##   -> https://zenko.readthedocs.io/en/latest/reference/apis/cloudserver/bucket_operations/put_bucket_acl.html#put-bucket-acl
##
class BucketAclGrantHeadersNormer(NormalizerBase):

    NORMER_CONFIG_PATH = ['acl', 'grant_headers']

    def __init__(self, pluginref, *args, **kwargs):
        ##
        ## if bucket owner is not explicitly mentioned by any policy
        ## here, give hm this default permissions, set it to empty
        ## to disable owner defaulting
        ##
        self._add_defaultsetter(kwargs,
          'owner_default_access', DefaultSetterConstant('full')
        )

        self._add_defaultsetter(kwargs,
          'grantees', DefaultSetterConstant({})
        )

        self._add_defaultsetter(kwargs,
          'grantee_defaults', DefaultSetterConstant({})
        )

        super(BucketAclGrantHeadersNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        gdef = my_subcfg['grantee_defaults']

        ## note: for some reason only email works here for
        ##   zenko atm while id for example fails
        setdefault_none(gdef, 'id_attribute', 'email')
        setdefault_none(gdef, 'is_user_ref', True)

        bcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        bown = bcfg['owner']['name']

        own_def = my_subcfg['owner_default_access']

        if own_def:
            ## check if owner is explicitly mentioned anywhere,
            ## otherwise make default access for it
            owner_seen = False

            for k, v in my_subcfg['grantees'].items():
                if not v:
                    ## skip emtpy "class"
                    continue

                for kk, vv in v.items():
                    vv = vv or {}
                    un = setdefault_none(vv, 'name', kk)

                    if un == bown:
                        owner_seen = True
                        break

                if owner_seen:
                    break

            if not owner_seen:
                setdefault_none(my_subcfg['grantees'], own_def, {}).update({
                  bown: None,
                })

        id_attr_remap = {
          'id': 'arn',
        }

        pa_root = self.get_parentcfg(cfg, cfgpath_abs, level=6)
        usr_cfg_root = pa_root['users']

        ## check for all user refed users if they are valid config
        ## users and also auto convert to correct attribute
        for k, v in my_subcfg['grantees'].items():
            if not v:
                ## skip emtpy "class"
                continue

            for kk in list(v.keys()):
                vv = v[kk] or {}
                v[kk] = vv

                un = setdefault_none(vv, 'name', kk)

                uref = vv.pop('is_user_ref', None)
                if uref is None:
                    uref = gdef['is_user_ref']

                if not uref:
                    continue

                ## check if can map name to any valid config user
                ## auto convert given "name" to correct user
                ## attribute used for header
                ucfg = usr_cfg_root['users_by_name'].get(un, None)

                ansible_assert(ucfg,
                   "given bucket acl user name '{}' is not a valid"\
                   " user ref, it does not map to any config user".format(un)
                )

                ida = vv.get('id_attribute', None)
                if ida is None:
                    ida = gdef['id_attribute']

                uattr = id_attr_remap.get(ida, None) or ida
                vv['name'] = ucfg['config'][uattr]

        c = setdefault_none(bcfg, 'configs', {})
        c = setdefault_none(c, 'bucket_acl', {})

        gdef.pop('is_user_ref', None)

        c.update({
          'object_path': bcfg['name'],
          'header_grantees': my_subcfg['grantees'],
          'header_grantee_defaults': gdef,
        })

        return my_subcfg



class BucketPolicyNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          ## note: current latest stable version of policy format
          'version', DefaultSetterConstant('2012-10-17')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          BucketPolicyStatementInstNormer(pluginref),
        ]

        super(BucketPolicyNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['bucket_policy']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        exp_map = {}
        stats = my_subcfg['statements']

        if stats:
            exp_map['Version'] = my_subcfg['version']

            tmp = []

            for x in stats.values():
                x = copy.deepcopy(x)

                ##
                ## note: some "more advanced" policy fields are atm
                ##   not supported by zenko unfortunately, filter them out
                ##
                for y in ['Sid']:
                    x.pop(y, None)

                tmp.append(x)

            exp_map['Statement'] = tmp

        my_subcfg['_export_formats'] = {
          'map': exp_map,
          'str': None,
        }

        if exp_map:
            my_subcfg['_export_formats']['str'] = json.dumps(
              exp_map##, indent=2
            )

        return my_subcfg



class BucketPolicyStatementInstNormer(NormalizerNamed):

    @property
    def name_key(self):
        return 'Sid'

    @property
    def config_path(self):
        return ['statements', SUBDICT_METAKEY_ANY]



class StorageBackendsRootNormer(NormalizerBase):

    US_EAST_STANDARD_MAPKEY = 'us-east-1'

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'enable_dummy_default_us_east', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          StorageBackendsAllNormer(pluginref),
        ]

        super(StorageBackendsRootNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['storage_backends']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## having a us_east location is mandatory, handle it
        us_east_finds_by_key = {}
        us_east_finds_by_copy = []

        backends = setdefault_none(my_subcfg, 'backends', {})

        for k, v in backends.items():
            for kk, vv in v.items():
                vv = vv or {}
                locn = vv.get('name', None) or kk

                make_us_east = vv.get('us_east_standard', False)

                if locn == self.US_EAST_STANDARD_MAPKEY:
                    vv['mapkey'] = kk
                    us_east_finds_by_key.setdefault(k, []).append(vv)
                    continue
 
                if make_us_east:
                    if isinstance(make_us_east, bool)\
                       or make_us_east.get('enabled', False):

                       vv['type'] = k
                       vv['mapkey'] = kk
                       us_east_finds_by_copy.append(vv)

        if us_east_finds_by_key:
            ## there can only be one ever
            btypes = list(us_east_finds_by_key.keys())
            ansible_assert(len(btypes) == 1,
               "multiple definition of '{}' standard location for"\
               " different backend types {} found but there can"\
               " only be one:\n{}".format(self.US_EAST_STANDARD_MAPKEY,
                   btypes, us_east_finds_by_key
               )
            )

            btypes = btypes[0]
            us_east = next(iter(us_east_finds_by_key.values()))

            ansible_assert(len(us_east) == 1,
               "multiple definition of '{}' standard location of"\
               " backend type '{}' found but there can"\
               " only be one:\n{}".format(self.US_EAST_STANDARD_MAPKEY,
                   btypes, us_east_finds_by_key
               )
            )

            us_east = us_east[0]
            us_east.pop('mapkey')

            ansible_assert(not us_east_finds_by_copy,
               "found one explicit definition of standard location '{0}'"\
               " (of backend type '{1}') but also '{2}' other location which"\
               " are flagged to create standard location copies from"\
               " themselves, but there can always only be one '{0}'"\
               " standard location, correct your config:\n{3}".format(
                  self.US_EAST_STANDARD_MAPKEY, btypes,
                  len(us_east_finds_by_copy), us_east_finds_by_copy
               )
            )

            ## user defined us-east standard, no defaulting needed

        elif us_east_finds_by_copy:
            ## there can only be one ever
            ansible_assert(len(us_east_finds_by_copy) == 1,
               "found more than one backend location which is flagged"\
               " to create '{}' standard location as copy from itself,"\
               " but there can only ever be one standard"\
               " location:\n{}".format(self.US_EAST_STANDARD_MAPKEY,
                   us_east_finds_by_copy
               )
            )

            ## create standard us_east as copy from source location
            us_east_src = us_east_finds_by_copy[0]

            mkey = us_east_src.pop('mapkey')
            loctype = us_east_src.pop('type')
            make_us_east = us_east_src.pop('us_east_standard')

            us_east = copy.deepcopy(us_east_src)
            us_east_src['us_east_standard'] = make_us_east

            if isinstance(make_us_east, collections.abc.Mapping):
                ## apply potential us-east overrides
                us_east = merge_dicts(us_east,
                  make_us_east.get('overwrites', None) or {}
                )

            tmp = setdefault_none(backends, loctype, {})
            tmp[self.US_EAST_STANDARD_MAPKEY] = us_east

        else:
            ansible_assert(my_subcfg['enable_dummy_default_us_east'],
               "Mandatory standard backend location '{0}' missing,"\
               " either define one explicitly, mark another existing"\
               " backend location to create '{0}' as a copy of it with"\
               " the 'us_east_standard' attribute or allow normalizer"\
               " to create a default dummy standard location if you"\
               " dont plan to use it by setting {1} to true".format(
                   self.US_EAST_STANDARD_MAPKEY,
                   '.'.join(cfgpath_abs + ['enable_dummy_default_us_east'])
               )
            )

            ## create mem based dummy us-east-1 backend assuming
            ## it is not used productively
            us_east = {}
            mem_backs = setdefault_none(backends, 'mem', {})
            mem_backs[self.US_EAST_STANDARD_MAPKEY] = us_east

        ## note: it seems not to be necessary to set legacyAwsBehavior
        ##   to true for us-east standard but still makes sense on default
        setdefault_none(setdefault_none(us_east,
           'passthrough_settings', {}
        ), 'legacyAwsBehavior', True)

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        exp_cfgs = {}
        cfg_az_storage = {}

        for k, v in my_subcfg['backends']['azure'].items():
            az_cont = v['azure_container']
            az_acc = v['storage_account']
            az_acc_ref = None

            if az_acc['managed']:
                cfg_accs = setdefault_none(setdefault_none(cfg_az_storage,
                   'storage_accounts', {}), 'accounts', {}
                )

                tmp = { 'short_name': az_acc['short_name'],
                  'full_name': az_acc['full_name'],
                  'config': az_acc.get('config', None) or {},
                }

                t2 = az_acc.get('name_prefix', None)

                if t2:
                    tmp['name_prefix'] = t2

                t2 = az_acc.get('name_suffix', None)

                if t2:
                    tmp['name_suffix'] = t2

                t2 = az_acc.get('resgrp', None)

                if t2:
                    tmp['resgrp'] = t2

                az_acc_ref = az_acc['full_name']
                cfg_accs[az_acc_ref] = tmp

            if az_cont['managed']:
                cfg_conts = setdefault_none(setdefault_none(cfg_az_storage,
                   'storage_containers', {}), 'containers', {}
                )

                tmp = { 'name': az_cont['name'],
                  'config': az_cont.get('config', None) or {},
                }

                cfg_conts[az_cont['name']] = tmp

                if az_acc_ref:
                    tmp['account_ref'] = az_acc_ref
                else:
                    tmp['config'].update(
                      storage_account_name=az_acc['full_name'],
                      resource_group=az_acc['resgrp']['name']
                    )

        if cfg_az_storage:
            cfg_az_storage['hide_secrets'] = pcfg['hide_secrets']
            exp_cfgs['azure_storage'] = cfg_az_storage

        if exp_cfgs:
            my_subcfg['_export_cfgs'] = exp_cfgs

        return my_subcfg



class StorageBackendsAllNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          StorageBackendMemInstNormer(pluginref),
          StorageBackendAzureInstNormer(pluginref),
        ]

        super(StorageBackendsAllNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['backends']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## check if we have a default backend
        ## already defined, choose one otherwise
        default_on = []
        first = None

        check_duplicates = {}
        backends_by_name = {}

        for k, v in my_subcfg.items():
            for kk, vv in v.items():
                check_duplicates.setdefault(vv['name'], {}).setdefault(
                  k, []
                ).append(vv)

                backends_by_name[vv['name']] = vv

                if not first:
                    first = vv

                if vv['default_backend']:
                    default_on.append(vv)

        ansible_assert(len(default_on) < 2,
          "only one backend can be the default, but '{}'"\
          " with marked as default:\n{}".format(len(default_on), default_on)
        )

        if not default_on:
            ## if no one had default on, make first one the auto-default
            first['default_backend'] = True
            default_on.append(first)

        default_on = default_on[0]

        ## test for duplicates
        for k, v in check_duplicates.items():
            btypes = list(v.keys())

            ansible_assert(len(btypes) == 1, \
               "identical location backend name '{}' re-used for different"\
               " backend types {}, names must be globally"\
               " unique:\n{}".format(k, btypes, v)
            )

            v = next(iter(v.values()))
            btypes = btypes[0]

            ansible_assert(len(v) == 1, \
               "identical location backend name '{}' re-used for different"\
               " backends of type '{}', names must be globally"\
               " unique:\n{}".format(k, btypes, v)
            )

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        pcfg['backends_by_name'] = backends_by_name

        if default_on:
            pcfg['default_backend'] = default_on

        return my_subcfg



class StorageBackendInstNormerBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'default_backend', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'env_vars', DefaultSetterConstant({})
        )

        self._add_defaultsetter(kwargs,
          'passthrough_settings', DefaultSetterConstant({})
        )

        super(StorageBackendInstNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )


    def _create_cfgfile_entry(self, entry, cfg, my_subcfg, cfgpath_abs):
        psets = my_subcfg['passthrough_settings']

        setdefault_none(psets, 'objectId', my_subcfg['name'])
        setdefault_none(psets, 'legacyAwsBehavior', False)

        ## create fitting config settings for this backend
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=4)

        tmp = ['cfgfiles', 'location_config',
          'settings'
        ]

        for x in tmp:
            pcfg = setdefault_none(pcfg, x, {})

        entry = merge_dicts(entry, psets)
        pcfg[my_subcfg['name']] = entry



class StorageBackendMemInstNormer(StorageBackendInstNormerBase):

    @property
    def config_path(self):
        return ['mem', SUBDICT_METAKEY_ANY]

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        self._create_cfgfile_entry({
            "type": "mem",
            "details": {},
          }, cfg, my_subcfg, cfgpath_abs
        )

        return my_subcfg


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ##
        ## note that zenko app itself is relative lenient for its
        ## backend aka location contrain names but some aws tools
        ## or ansible modules can be more strict here, so apply
        ## some safety defaulting here to be on the safe side
        ##
        my_subcfg['name'] = norm_name_s3(my_subcfg['name'])
        return my_subcfg



class StorageBackendAzureInstNormer(StorageBackendInstNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          StBackAzStoreAccountNormer(pluginref),
          StBackAzContNormer(pluginref),
        ]

        super(StorageBackendAzureInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['azure', SUBDICT_METAKEY_ANY]


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## create fitting config settings for this backend
        akey_cfg = my_subcfg['storage_account']['access_key']

        if akey_cfg['by_env']:
            ##
            ## note that zenko app itself is relative lenient for its
            ## backend aka location contrain names but some aws tools
            ## or ansible modules can be more strict here, so apply
            ## some safety defaulting here to be on the safe side
            ##
            ## update: we have a bit of a conundrum here, technically
            ##   s3-api and zenko allows anything hostnamy here, but
            ##   when having "-" in the name we cannot induce secrets
            ##   as env-vars anymore because the only allowed special
            ##   chars in envvar names is the underscore, so the only
            ##   safe variant here is to disallow all special chars
            ##   like for azure storage accounts
            ##
            ## update.2: we dont should do this norming in general,
            ##   but only when azure and env-vars is done, because
            ##   this is too restrictive in general as we for example
            ##   need a backend location eith
            ##   US_EAST_STANDARD_MAPKEY (containing '-')
            ##
            my_subcfg['name'] = norm_name_azure_store_acc(my_subcfg['name'])

        self._create_cfgfile_entry({
            "type": "azure",
            "details": {
              "azureStorageEndpoint": \
                 my_subcfg['storage_account']['endpoint_url'],
              "azureStorageAccountName": \
                 my_subcfg['storage_account']['full_name'],
              "azureContainerName": my_subcfg['azure_container']['name'],
              "azureStorageAccessKey": akey_cfg['value'],
            },
          }, cfg, my_subcfg, cfgpath_abs
        )

        if akey_cfg['by_env']:
            ##
            ## note: zenko uses a predefined naming pattern for
            ##   overwriting keys / secrets by env, which
            ##   is: "{{region-name}}_{{ENV_VAR_NAME}}", see also:
            ##
            ##      -> https://s3-server.readthedocs.io/en/latest/USING_PUBLIC_CLOUDS.html#id2
            ##
            bad_chars = ['-', '/']

            for bc in bad_chars:
                ansible_assert(bc not in my_subcfg['name'],
                   "azure secret key was set to be obtained by environment"\
                   " variable, for that case given azure storage backend"\
                   " name '{}' is invalid because it contains one of these"\
                   " characters not being allowed for environment key"\
                   " names: {}".format(my_subcfg['name'], bad_chars)
                )

            akey_envvar = "{}_AZURE_STORAGE_ACCESS_KEY".format(
              my_subcfg['name']
            )

            my_subcfg['env_vars']['access_key'] = akey_envvar

            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=4)
            pcfg = pcfg['docker']['services']['cloudserver']
            pcfg = pcfg['templates']['templates']

            pcfg['backend_settings_azure_{}'.format(my_subcfg['name'])] = {
              'environment': {
                 akey_envvar: None,
              }
            }

        exp_configs = {}

        if akey_cfg['from'] == "ansible_azure_read":
            exp_configs['get_stacc_keys'] = {
              'account_name': my_subcfg['storage_account']['full_name'],
              'account_resoure_group': \
                 my_subcfg['storage_account']['resgrp']['name'],
            }

        if exp_configs:
            my_subcfg['_export_configs'] = exp_configs

        return my_subcfg



class StBackAzStoreAccountNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'managed', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'name_prefix', DefaultSetterConstant('')
        )

        self._add_defaultsetter(kwargs,
          'name_suffix', DefaultSetterConstant('')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          StBackAzStAccAccessKeyNormer(pluginref),
        ]

        super(StBackAzStoreAccountNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['storage_account']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        ## default short-name to parent name
        sn = setdefault_none(my_subcfg, 'short_name', pcfg['name'])

        ## default build fullname when necessary
        fn = my_subcfg.get('full_name', None)

        if not fn:
            fn = my_subcfg['name_prefix'] + sn + my_subcfg['name_suffix']
            fn = norm_name_azure_store_acc(fn)
            my_subcfg['full_name'] = norm_name_azure_store_acc(fn)

        ## default build endpoint url when necessary
        eu = my_subcfg.get('endpoint_url', None)

        if not eu:
            eu = to_azure_endpoint_url(fn)
            my_subcfg['endpoint_url'] = eu

        rgrp = my_subcfg.get('resgrp', None)

        if rgrp:
            if not isinstance(rgrp, collections.abc.Mapping):
                ## assume simple string mapping
                rgrp = {
                  'name': rgrp,
                }

                my_subcfg['resgrp'] = rgrp

        return my_subcfg



class StBackAzStAccAccessKeyNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'from', DefaultSetterConstant('cfg_verbatim')
        )

        self._add_defaultsetter(kwargs,
          'by_env', DefaultSetterConstant(False)
        )

        super(StBackAzStAccAccessKeyNormer, self).__init__(
           pluginref, *args, **kwargs
        )


    @property
    def config_path(self):
        return ['access_key']

    @property
    def simpleform_key(self):
        return 'value'


    def _handle_from_special_cfg_verbatim(self, cfg, my_subcfg, cfgpath_abs):
        v = my_subcfg.get('value', None)

        ansible_assert(v,
          "when using from method '{}' caller must provide an"\
          " storage account access key verbatim using the 'value'"\
          " field".format(my_subcfg['from'])
        )


    def _handle_special_from_base_envvar_type(self, cfg,
        my_subcfg, cfgpath_abs
    ):
        v = my_subcfg.get('value', None)

        ansible_assert(not v,
          "dont set storage account access key credentials directly"\
          " per config value field when using from method '{}'".format(
            my_subcfg['from']
          )
        )

        my_subcfg['value'] = "<<<set-by-env>>>"
        my_subcfg['by_env'] = True


    def _handle_from_special_ansible_azure_read(self,
        cfg, my_subcfg, cfgpath_abs
    ):
        self._handle_special_from_base_envvar_type(cfg,
            my_subcfg, cfgpath_abs
        )


    def _handle_from_special_env_var(self, cfg, my_subcfg, cfgpath_abs):
        self._handle_special_from_base_envvar_type(cfg,
            my_subcfg, cfgpath_abs
        )


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        from_meth = getattr(self,
          '_handle_from_special_' + my_subcfg['from'], None
        )

        ansible_assert(from_meth,
          "Unsupported from method type '{}'".format(my_subcfg['from'])
        )

        from_meth(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg



class StBackAzContNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'managed', DefaultSetterConstant(False)
        )

        super(StBackAzContNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['azure_container']



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self),
           *args, default_merge_vars=[
             'smabot_storage_zenko_docker_args_defaults',
             'smabot_storage_zenko_docker_args_extra_defaults',
           ],
           ##extra_merge_vars_ans=['extra_gitlab_config_maps'], 
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_storage_zenko_docker_args'

