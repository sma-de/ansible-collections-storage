
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections
import copy
import json


from ansible.errors import AnsibleOptionsError
from ansible.module_utils.six import string_types
from ansible.utils.display import Display

from ansible_collections.smabot.storage.plugins.module_utils.plugins.s3api_action import S3ApiBase
from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  merge_dicts, \
  setdefault_none

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()

##
## note: this would probably be better as module but currently we need
##   to be able to call other modules which is not possible from
##   inside a module atm (but fine for action plugins)
##
## note.2: currently there seems no senseable uptodate pylib for
##   backend handling, so in first iteration we will do heavy
##   backend api call hanlding directly here
##
## TODO: convert to pylib based module
##
##


##
## note: in principle there are 3 ways to define an ACL:
##
##   1. "canned acl": one string word with "x-amz-acl"
##         header to select a special predefined
##         scenario (private, public-read, ...), this
##         one is better handled directly by upstream
##         amazon aws module and therefore not supported here
##
##   2. simplified format with "grant-xxx" header,
##      this is handled by this class (this might be specific to zenko??)
##
##   3. full explicit xml based acl format, this is
##      currently very buggy and seemingly unworking
##      for zenko, so we dont use it atm
##
## see also:
##   -> https://zenko.readthedocs.io/en/latest/reference/apis/cloudserver/bucket_operations/put_bucket_acl.html#put-bucket-acl
##
class ActionModule(S3ApiBase):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'object_path': (list(string_types)),

          ## TODO: support full acl and make it mutual exclusive to header grantees
          ##'acl_from_file': (list(string_types)),
          ##'acl_map': ([collections.abc.Mapping]),
          'header_grantees': ([collections.abc.Mapping]),
          'header_grantee_defaults': ([collections.abc.Mapping], {}),

          ## note: email seems actually to be the most compatible and stable one here
          'default_id_attribute': (list(string_types),
             'email', ['email', 'id', 'uri']
          ),

          ## TODO: will we ever do full stating here???
          ##'state': (list(string_types), 'present', ['present', 'absent']),
        })

        return tmp


    def _get_diff_recv(self, acl_old, acl_new, **kwargs):
        is_map = True

        if isinstance(acl_old, list):
            itx = range(0, len(acl_old))
            is_map = False
        elif isinstance(acl_old, collections.abc.Mapping):
            ## assume map on default
            itx = acl_old.keys()
        else:
            return {
              'old': acl_old, 'new': acl_new,
            }

        cur_diff = {}

        for x in itx:
            v = acl_old[x]
            vo = acl_new[x]

            if v == vo:
                # no diff here => noop
                continue

            k = x

            if not is_map:
                k = "[{}]".format(x)

            if isinstance(v, collections.abc.Mapping) \
              and isinstance(vo, collections.abc.Mapping):
                ## both are mapping, recurse down as mapping
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            elif isinstance(v, list) and isinstance(vo, list):
                ## both are lists, recurse down as lists
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            else:
                cur_diff_x = {'old': v, 'new': vo}

            if cur_diff_x:
                cur_diff[k] = cur_diff_x

        return cur_diff


    def _compare_acls(self, acl_old, acl_new):
        return self._get_diff_recv(acl_old, acl_new)


    def run_specific(self, result):
        ##state = self.get_taskparam('state')
        state = 'present'

        obj_path = self.get_taskparam('object_path')

        head_grants = self.get_taskparam('header_grantees')
        head_grants_defs = self.get_taskparam('header_grantee_defaults')

        def_id_attr = self.get_taskparam('default_id_attribute')

        if state == 'present':
            ansible_assert(head_grants,
              "currently only setting per grant headers is implemented!"
            )

            if head_grants:
                display.vv(
                   "S3API_MANAGE_ACL :: use header grants method"
                )

                acl_level = {
                  'read': None,
                  'write': None,
                  'read_acp': None,
                  'write_acp': None,
                  'full': 'full-control',
                }

                id_attr_remaps = {
                  'email': 'emailAddress',
                }

                ## build headers based on current config
                acl_headers = {}

                for k, v in head_grants.items():
                    ansible_assert(k in acl_level,
                      "unsupported acl grant level '{}', must be one"\
                      " of these:\n{}".format(k, list(acl_level.keys()))
                    )

                    if not v:
                        ## skip emtpy "class"
                        continue

                    ax = acl_level[k] or k

                    hdr_name = "x-amz-grant-" + ax.replace('_', '-')
                    hdr_users = []

                    for kk, vv in v.items():
                        vv = vv or {}

                        un = setdefault_none(vv, 'name', kk)

                        vv = merge_dicts(copy.deepcopy(head_grants_defs), vv)

                        ida = setdefault_none(vv, 'id_attribute', def_id_attr)
                        ida = id_attr_remaps.get(ida, None) or ida

                        hdr_users.append('{}="{}"'.format(ida, un))

                    acl_headers[hdr_name] = ','.join(hdr_users)

                if acl_headers:
                    ## read current acl settings (for later compare)
                    display.vv(
                      "S3API_MANAGE_ACL :: get object acl before"\
                      " operation ..."
                    )

                    orig_acl = self.get_object_acl(obj_path)

                    display.vvv(
                      "S3API_MANAGE_ACL :: acl of s3 object '{}' before"\
                      " operation:\n{}".format(obj_path,
                         json.dumps(orig_acl, indent=2)
                      )
                    )

                    ## put acl request based on acl grant headers
                    display.vv(
                      "S3API_MANAGE_ACL :: apply acl headers based on"\
                      " given module config ..."
                    )

                    self.put_object_acl(obj_path, headers=acl_headers)

                    ## read acl settings post put and compare it to one
                    display.vv(
                      "S3API_MANAGE_ACL :: get object acl after"\
                      " operation ..."
                    )

                    ##
                    ## note: used upstream http code has seemingly a
                    ##   builtin cache so when redo-ing the same request
                    ##   here we get a cached response on default, which
                    ##   is obiously not what we need here, set force
                    ##   to avoid this
                    ##
                    post_acl = self.get_object_acl(obj_path,
                      fwargs={'force': True}
                    )

                    result['acl'] = post_acl

                    display.vvv(
                      "S3API_MANAGE_ACL :: acl of s3 object '{}' after"\
                      " operation:\n{}".format(obj_path,
                         json.dumps(post_acl, indent=2)
                      )
                    )

                    acl_diff = self._compare_acls(orig_acl, post_acl)

                    if acl_diff:
                        result['changed'] = True
                        result['change_type'] = 'updated'
                        result['diff'] = acl_diff

        return result

