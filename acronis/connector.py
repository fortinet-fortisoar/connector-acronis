"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('acronis')


class Acronis(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('execute [{}]'.format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params, self._info_json.get('name'), self._info_json.get('version'), **kwargs)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        logger.info('starting health check')
        return _check_health(config, self._info_json.get('name'), self._info_json.get('version'))
