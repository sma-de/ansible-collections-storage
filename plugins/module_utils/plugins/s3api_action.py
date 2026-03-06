
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import collections
import json

from ansible.errors import \
  AnsibleAssertionError,\
  AnsibleOptionsError,\
  AnsibleError

####from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction
from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert
from ansible.utils.display import Display


display = Display()


class S3ApiBase(BaseAction):

    def __init__(self, *args, **kwargs):
        super(S3ApiBase, self).__init__(*args, **kwargs)


    @property
    def argspec(self):
        tmp = super(S3ApiBase, self).argspec

        tmp.update({
          ##MAGIC_ARGSPECKEY_META: {
          ##   'mutual_exclusions': [
          ##      ['session_token', 'access_key'],
          ##      ['session_token', 'secret_key'],
          ##   ],
          ##},

          'endpoint_url': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': ['auth_s3api_url',
                  'auth_aws_s3api_url', 'auth_url_s3api',
                  'auth_url',
                  ## mimick standard env vars
                  'AWS_URL',
                ],
##         'env': '',
            },
          },

          ##'session_token': { ## TODO: only when real usage
          ##  'type': list(string_types),
          ##  'defaulting': {
          ##     'ansvar': [
          ##        'auth_nexus_token', 'auth_sonatypenx_token',
          ##        'auth_token_sonanexus', 'auth_token',
          ##      ],
          ##     'fallback': ''
          ##  },
          ##},

          'region': (list(string_types), 'us-east-1'),

          'access_key': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': [
                  'auth_s3api_access', 'auth_s3api_accesskey',
                  'auth_aws_s3api_accesskey', 'auth_accesskey',
                  ## mimick standard env vars
                  'AWS_ACCESS_KEY_ID', 'AWS_ACCESS_KEY'
                ],
               'fallback': ''
            },
          },

          'secret_key': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': [
                  'auth_s3api_secret', 'auth_s3api_secretkey',
                  'auth_aws_s3api_secretkey', 'auth_secretkey',
                  ## mimick standard env vars
                  'AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_KEY'
                ],
               'fallback': ''
            },
          },

          'validate_certs': {
            'type': [bool],
            'defaulting': {
               'ansvar': ['auth_s3api_certval', 'auth_aws_s3api_certval'],
               'fallback': True
            },
          },
        })

        return tmp

    @property
    def rest_api_basepath(self):
        return ""

    @property
    def s3api_url(self):
        return self.get_taskparam('endpoint_url')

    @property
    def s3api_url_restapi(self):
        return "{}/{}".format(self.s3api_url, self.rest_api_basepath)

    @property
    def s3api_auth_akey(self):
        return self.get_taskparam('access_key')

    @property
    def s3api_auth_skey(self):
        return self.get_taskparam('secret_key')


    def query_s3_restapi(self, resource, auth=True, method=None,
        url_query=None, body=None, srcfile=None, fwargs=None, **kwargs
    ):
        display.vv("query_s3 fwargs: {}".format(fwargs))
        modargs = fwargs or {}

        ## note: for s3api we want to have the response content
        ##   most of the time independend of the exact api call
        modargs.setdefault('return_content', True)

        if body or srcfile:
            method = method or 'POST'

            if body:
                if isinstance(body, (list, collections.abc.Mapping)):
                    body = json.dumps(body).encode("utf-8")
                    modargs.setdefault('headers', {}).update({
                      'Content-Type': 'application/json',
                    })

                elif isinstance(body, string_types):
                    body = body.encode("utf-8")

                modargs['body'] = body

            else:
                ## we need the actual bytes here for the amazon signing stuff!!!
                ansible_assert(False, "srcfile not yet supported")
                modargs['src'] = srcfile
        else:
            ##
            ## note: some stricter s3 implementations (e.g. zenko) need
            ##   this header even when no body is send, but it seems
            ##   that the upstream amazon lib does not add it itself
            ##   in such cases (like for example curl does)
            ##
            kwargs.setdefault('headers', {}).update({
              "x-amz-content-sha256": \
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            })

        method = method or 'GET'
        modargs['method'] = method

        url = self.s3api_url_restapi
        url_sfx = resource

        if url_sfx[0] != '/' and url[-1] != '/':
            url_sfx = '/' + url_sfx

        if url_query:
            url_sfx += '?'

            if isinstance(url_query, collections.abc.Mapping):
                tmp = []

                for k, v in url_query.items():
                    tmp.append("{}={}".format(k, v))

                url_sfx += '&'.join(tmp)
            else:
                ## assume preformatted string
                url_sfx += url_query

        modargs['url'] = url + url_sfx
        modargs['validate_certs'] = self.get_taskparam('validate_certs')

        passthrough_args = ['status_code', 'headers']

        for pa in passthrough_args:
            tmp = kwargs.pop(pa, None)

            if tmp:
                modargs[pa] = tmp

        if auth:
            # handle authing credentials when needed
            secret_given = False
            token_given = False

            modkey_map = {
              'access_key': 'url_username',
              'secret_key': 'url_password',
              'session_token': 'url_password',
            }

            for apk, apv in modkey_map.items():
                if modargs.get(apv, None):
                    ## if we already have a password or
                    ## user set, dont try setting it anymore
                    continue

                ## optionally allow calling method to
                ## overwrite used auth credentials
                tmp = kwargs.pop(apv, None)

                if not tmp:
                    if apk == 'access_key':
                        tmp = self.s3api_auth_akey
                    elif apk == 'secret_key':
                        tmp = self.s3api_auth_skey
                    else:
                        tmp = self.get_taskparam(apk)

                if tmp:
                    modargs[apv] = tmp

                    if apk == 'secret_key':
                        secret_given = True
                    elif apk == 'session_token':
                        token_given = True

            if not secret_given and not token_given:
                e = AnsibleOptionsError(
                   "S3 api rest call to '{}' needs authorisation,"\
                   " caller must either provide a secret key or a"\
                   " session token".format(modargs['url'])
                )

                e.no_s3api_auth = True
                raise e

            ## handle amazon aws request signing v4
            akey = modargs.pop('url_username')
            secret = modargs.pop('url_password')

            from botocore.awsrequest import AWSRequest
            from botocore.auth import SigV4Auth
            from botocore.credentials import Credentials

            rq = AWSRequest(modargs['method'], url=modargs['url'],
              headers=modargs.get('headers', None),
              data=modargs.get('body', None),
            )

            creds = Credentials(akey, secret)

            SigV4Auth(creds, 's3',
              self.get_taskparam('region')
            ).add_auth(rq)

            rq_signed = rq.prepare()

            modargs['url'] = rq_signed.url
            modargs['headers'] = rq_signed.headers
            modargs['body'] = rq_signed.body

        return self.exec_module('ansible.builtin.uri',
            modargs=modargs, **kwargs
        )


    def handle_xml_result(self, res, parse='as_dict', **kwargs):
        if not parse:
            return res['content']

        if parse == 'as_dict':
            import xmltodict
            return xmltodict.parse(res['content'])

        ansible_assert(False, "not yet implemented")


    def get_object_acl(self, obj_path, **kwargs):
        return self.handle_xml_result(self.query_s3_restapi(obj_path,
          url_query='acl', **kwargs
        ), **kwargs)


    def put_object_acl(self, obj_path, **kwargs):
        self.query_s3_restapi(obj_path,
           method='PUT', url_query='acl', **kwargs
        )

