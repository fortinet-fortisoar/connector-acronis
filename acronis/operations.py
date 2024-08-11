"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests
import json
import base64
import time
from base64 import b64encode
from connectors.core.utils import update_connnector_config
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('acronis')


class Acronis:
    def __init__(self, config):
        self.base_url = config.get("server_url")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        if self.base_url.startswith('https://') or self.base_url.startswith('http://'):
            self.base_url = self.base_url.strip('/')
        else:
            self.base_url = 'https://{0}'.format(self.base_url.strip('/'))
        self.access_token = config.get('token')
        self.verify_ssl = config.get("verify_ssl")
        self.headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
        }

    def make_request(self, connector_name, connector_version, endpoint, config, method='GET', flag=False,
                     params=None, data=None):
        try:
            if self.access_token:
                self.validate_token_for_cyops_config(config, connector_name, connector_version)
            if flag == True:
                self.headers['Authorization'] = 'Bearer {0}'.format(self.access_token)
            url = '{0}{1}'.format(self.base_url, endpoint)
            logger.info('Request URL {0}'.format(url))

            response = requests.request(method, url, data=data, headers=self.headers, verify=self.verify_ssl,
                                        params=params)

            if response.status_code in [200, 201, 204, 206]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            elif response.status_code == 404:
                return response
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['ERROR_DESCRIPTION']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format('SSL certificate validation failed'))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format('The request timed out while trying to connect to the remote server'))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))

    def validate_token_for_cyops_config(self, config, connector_name, connector_version):
        try:
            ts_now = int(time.time())
            if not config.get('token'):
                logger.error('Error occured while connecting server: Unauthorized')
                raise ConnectorError('Error occured while connecting server: Unauthorized')
            expires = config.get('expiresOn', 0)
            if ts_now > expires:
                new_token, exp_time = self.generate_token(connector_name, connector_version, config)
                config['token'] = new_token
                config['expiresOn'] = exp_time
                update_connnector_config(connector_name, connector_version, config, config.get('config_id'))
            else:
                logger.info("Acronis: Valid Acronis Token")
                self.access_token = config.get('token')
        except Exception as err:
            logger.error("Failure {0}".format(str(err)))
            raise ConnectorError(str(err))

    def generate_token(self, connector_name, connector_version, config):
        params = {'client_id': self.client_id, 'client_secret': self.client_secret}
        encoded_client_creds = b64encode(f'{self.client_id}:{self.client_secret}'.encode('ascii'))
        basic_auth = {'Authorization': 'Basic ' + encoded_client_creds.decode('ascii')}
        self.headers = {'Content-Type': 'application/x-www-form-urlencoded', **basic_auth}

        response = requests.request('POST', f'{self.base_url}/api/2/idp/token',
                                    headers={'Content-Type': 'application/x-www-form-urlencoded', **basic_auth},
                                    data={'grant_type': 'client_credentials'})
        response = response.json()
        access_token = response['access_token']
        expires_in = response['expires_on']
        if response:
            return access_token, expires_in

    def build_payload(self, params):
        result = {k: v for k, v in params.items() if v is not None and v != ''}
        return result

    def encode_query(self, query):
        json_query = json.dumps(query).encode()
        encoded_query = base64.b64encode(json_query).decode("ascii")
        return encoded_query


def create_alert(config, params, connector_name, connector_version, **kwargs):
    obj = Acronis(config)
    params = obj.build_payload(params)
    if params.get('type'):
        alert_types_ids = get_alert_types(config, params, connector_name, connector_version, response_type='list')
        params['type'] = alert_types_ids    
    if params.get('title'):
        params.update({"details": {"title": params.get('title')}})
    if params.get('category'):
        params.update({"category": {"title": params.get('category')}})
    if params.get('description'):
        params.update({"description": {"title": params.get('description')}})
    response = obj.make_request(connector_name, connector_version, endpoint='/api/alert_manager/v1/alerts', flag=True,
                                config=config, method='POST', data=json.dumps(params))
    return response


def get_alerts(config, params, connector_name, connector_version, **kwargs):
    obj = Acronis(config)
    params = obj.build_payload(params)
    endpoint = '/api/alert_manager/v1/alerts'
    if params.get('alerts_id'):
        endpoint = '/api/alert_manager/v1/alerts/{alerts_id}'.format(alerts_id=params.get('alerts_id'))
        params.pop('alerts_id')
    response = obj.make_request(connector_name, connector_version, endpoint=endpoint, config=config, flag=True,
                                 params=params)
    return response


def get_alert_types(config, params, connector_name, connector_version, response_type='list', **kwargs):
    obj = Acronis(config)
    params = obj.build_payload(params)
    response = obj.make_request(connector_name, connector_version, endpoint='/api/alert_manager/v1/types', flag=True,
                                config=config, params=params)
    items = response.get('items')
    types_list = []
    for each_item in items:
        types_list.append(each_item.get('id'))
    if response_type == 'list':
        return types_list
    else:
        return response


def delete_alert(config, params, connector_name, connector_version, **kwargs):
    obj = Acronis(config)
    params = obj.build_payload(params)
    response = obj.make_request(connector_name, connector_version,
                                endpoint='/api/alert_manager/v1/alerts/{alert_id}'.format(
                                    alert_id=params.get('alert_id')), flag=True,
                                config=config, method='DELETE', params=params)
    return response


def get_categories(config, params, connector_name, connector_version, **kwargs):
    obj = Acronis(config)
    params = obj.build_payload(params)
    response = obj.make_request(connector_name, connector_version, endpoint='/api/alert_manager/v1/categories', flag=True,
                                config=config, params=params)
    return response


def _check_health(config, connector_name, connector_version):
    try:
        obj = Acronis(config)
        token, expiration = obj.generate_token(connector_name, connector_version, config)
        config['token'] = token
        config['expiresOn'] = expiration
        update_connnector_config(connector_name, connector_version, config, config.get('config_id'))
        return True
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError(str(err))


operations = {
    "create_alert": create_alert,
    "get_alerts": get_alerts,
    "get_alert_types": get_alert_types,
    "delete_alert": delete_alert,
    "get_categories": get_categories
}
