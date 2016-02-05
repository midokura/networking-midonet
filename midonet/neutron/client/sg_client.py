# Copyright (C) 2016 Midokura SARL.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import inspect
import requests
import webob.exc as wexc

from neutron.common import exceptions as n_exc
from neutron.extensions import securitygroup

from oslo_config import cfg
from oslo_serialization import jsonutils


cfg.CONF.register_opt(cfg.StrOpt('sg_url', help="SG service URL"))
cfg.CONF.register_opt(cfg.IntOpt('sg_http_timeout',
                                 help="SG service HTTP timeout",
                                 default=60))
cfg.CONF.register_opt(cfg.BoolOpt('sg_verify_ssl',
                                  help="SG service HTTP verify SSL",
                                  default=False))
cfg.CONF.register_opt(cfg.StrOpt('sg_user',
                                 help="User to access SG service",
                                 default='admin_user_id'))
cfg.CONF.register_opt(cfg.StrOpt('sg_tenant',
                                 help="Tenant to access SG service",
                                 default='admin_tenant_id'))
cfg.CONF.register_opt(cfg.StrOpt('sg_role',
                                 help="Role to access SG service",
                                 default='admin'))

HTTP_OK = wexc.HTTPOk.code
HTTP_CREATED = wexc.HTTPCreated.code
HTTP_NO_CONTENT = wexc.HTTPNoContent.code
NEUTRON_ERROR = "NeutronError"

fault_map = {wexc.HTTPBadRequest.code: wexc.HTTPBadRequest,
             wexc.HTTPForbidden.code: wexc.HTTPForbidden,
             wexc.HTTPNotFound.code: wexc.HTTPNotFound,
             wexc.HTTPConflict.code: wexc.HTTPConflict,
             wexc.HTTPServiceUnavailable.code: wexc.HTTPServiceUnavailable,
             }
cls_map = dict(inspect.getmembers(securitygroup, inspect.isclass))
exc_cls_map = dict(inspect.getmembers(n_exc, inspect.isclass))


# SG Service acceptable MAX_QUERY_LENGTH is 10 * 1024 byte
# In GET query string, per resource "id=": 3 + uuid: 37 + and &: 1 = 41
# 10 * 1024 / 41 = 249, so set 200 for sub resource list size
QUERY_ID_SIZE = 200


class SGClientException(n_exc.NeutronException):
    message = 'Internal Server Error on SG service.(%(text)s)'


def get_err_cls(err_type):
    if not err_type:
        return None
    return cls_map.get(err_type) or exc_cls_map.get(err_type)


def do_request(context, method, resource,
               resource_id=None, body=None, filters=None, fields=None):
    headers = {}
    if context.is_admin and not context.user_id:
        # context is made by get_admin_context
        headers['X_USER_ID'] = cfg.CONF.sg_user
        headers['X_PROJECT_ID'] = cfg.CONF.sg_tenant
        headers['X_ROLES'] = cfg.CONF.sg_role
    else:
        headers['X_USER_ID'] = context.user_id
        headers['X_PROJECT_ID'] = context.tenant_id
        headers['X_ROLES'] = cfg.CONF.sg_role if context.is_admin else ''

    headers['Accept'] = 'application/json'
    kwargs = {}
    if body:
        headers['Content-Type'] = 'application/json'
        kwargs['data'] = jsonutils.dumps(body)
    kwargs['headers'] = headers

    if filters:
        kwargs['params'] = filters

    url = cfg.CONF.sg_url + '/' + resource
    if resource_id:
        url += "/%s" % resource_id

    resp = requests.request(method, url, timeout=cfg.CONF.sg_http_timeout,
                            verify=cfg.CONF.sg_verify_ssl,
                            **kwargs)
    if resp.status_code in [HTTP_OK, HTTP_CREATED]:
        return resp.json()
    elif resp.status_code == HTTP_NO_CONTENT:
        return None

    data = resp.json()
    err_dict = data.get(NEUTRON_ERROR, {})
    if 'type' in err_dict:
        err_cls = get_err_cls(err_dict["type"])
        if err_cls:
            e = err_cls()
            e.msg = err_dict["message"]
            raise e

    if resp.status_code in fault_map:
        raise fault_map[resp.status_code](resp.text)
    else:
        # internal server error
        raise SGClientException(text=resp.text)


def create_security_group(context, security_group):
    res = do_request(context, 'POST', 'security-groups', body=security_group)
    return res['security_group']


def update_security_group(context, id, security_group):
    res = do_request(context, 'PUT', 'security-groups', resource_id=id,
                     body=security_group)
    return res['security_group']


def delete_security_group(context, id):
    try:
        do_request(context, 'DELETE', 'security-groups', resource_id=id)
    except (wexc.HTTPNotFound, n_exc.NotFound):
        # Ignore not found error
        pass


def get_security_groups(context, filters=None):
    res = do_request(context, 'GET', 'security-groups', filters=filters)
    return res['security_groups']


def get_security_group(context, id):
    res = do_request(context, 'GET', 'security-groups', resource_id=id)
    return res['security_group']


def create_security_group_rule(context, security_group_rule):
    res = do_request(context, 'POST', 'security-group-rules',
                     body=security_group_rule)
    return res['security_group_rule']


def delete_security_group_rule(context, id):
    try:
        do_request(context, 'DELETE', 'security-group-rules', resource_id=id)
    except (wexc.HTTPNotFound, n_exc.NotFound):
        # Ignore not found error
        pass


def get_security_group_rules(context, filters=None):
    res = do_request(context, 'GET', 'security-group-rules', filters=filters)
    return res['security_group_rules']


def get_security_group_rule(context, id):
    res = do_request(context, 'GET', 'security-group-rules', resource_id=id)
    return res['security_group_rule']


def create_portbinding(context, portbinding):
    res = do_request(context, 'POST', 'portbindings', body=portbinding)
    return res['portbinding']


def update_portbinding(context, id, portbinding):
    res = do_request(context, 'PUT', 'portbindings', resource_id=id,
                     body=portbinding)
    return res['portbinding']


def delete_portbinding(context, id):
    try:
        do_request(context, 'DELETE', 'portbindings', resource_id=id)
    except (wexc.HTTPNotFound, n_exc.NotFound):
        # Ignore not found error
        pass


def _get_resources_by_ids(context, resource, ids):
    all_res = []
    start = 0
    resource_key = resource.replace('-', '_')
    while start < len(ids):
        res = do_request(context, 'GET', resource,
                         filters={'id': ids[start:start + QUERY_ID_SIZE]})
        all_res += res[resource_key]
        start += QUERY_ID_SIZE
    return all_res


def get_portbindings(context, port_ids=None):
    if port_ids is None:
        res = do_request(context, 'GET', 'portbindings')
        return res['portbindings']

    return _get_resources_by_ids(context, 'portbindings', port_ids)


def get_portbinding(context, id):
    try:
        res = do_request(context, 'GET', 'portbindings', resource_id=id)
    except (wexc.HTTPNotFound, n_exc.NotFound):
        # Ignore not found error
        return None
    return res['portbinding']


def get_security_groups_by_ids(context, ids):
    return _get_resources_by_ids(context, 'security-groups', ids)
