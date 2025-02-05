"""
utility.py
Helper file containing useful methods
"""
import collections
import json
import logging
import sys
import traceback

import splunk.entity as entity
import splunk.rest
from splunk.clilib.bundle_paths import make_splunkhome_path
import app_greynoise_declare
import requests
from requests.exceptions import ConnectionError, RequestException
from solnlib import conf_manager
from six import iteritems

from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure

import fields
from greynoise_exceptions import APIKeyNotFoundError

APP_NAME = app_greynoise_declare.ta_name

def get_conf_file(session_key, file, app=APP_NAME, realm="__REST_CREDENTIAL__#{app_name}#configs/conf-app_greynoise_settings".format(app_name=APP_NAME)):
    """
    Returns the conf object of the file
    :param session_key:
    :param file:
    :param app:
    :param realm:
    :return: Conf File Object
    """
    cfm = conf_manager.ConfManager(session_key, app, realm=realm)
    return cfm.get_conf(file)

def get_log_level(session_key):
    """
    Returns the log level from the GreyNoise config
    :param session_key:
    :return: level
    """
    # Get configuration file from the helper method defined in utility
    conf = get_conf_file(session_key, 'app_greynoise_settings')
    
    # Get logging stanza from the settings
    logging_config = conf.get("logging", {})
    logging_level = logging_config.get("loglevel", 'INFO')
    if logging_level == 'INFO':
        level = logging.INFO
    elif logging_level == 'DEBUG':
        level = logging.DEBUG
    elif logging_level == 'WARNING':
        level = logging.WARNING
    elif logging_level == 'ERROR':
        level = logging.ERROR
    elif logging_level == 'CRITICAL':
        level = logging.CRITICAL

    return level

def setup_logger(logger=None, log_format='%(asctime)s log_level=%(levelname)s, pid=%(process)d, tid=%(threadName)s, func_name=%(funcName)s, code_line_no=%(lineno)d | ',
                 level=logging.INFO, logger_name="greynoise_main", session_key=None, log_context='GreyNoise App'):
    if logger is None:
        logger = logging.getLogger(logger_name)
    
    # Get the logging level
    level = get_log_level(session_key)

    # Prevent the log messages from being duplicated in the python.log file
    logger.propagate = False
    logger.setLevel(level)

    log_name = logger_name + '.log'
    file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(
        ['var', 'log', 'splunk', log_name]), maxBytes=2500000, backupCount=5)
    
    # Adding the source of the logs to the log format
    log_format = log_format + '[{log_context}] %(message)s'.format(log_context=log_context)
    formatter = logging.Formatter(log_format)
    file_handler.setFormatter(formatter)

    logger.handlers = []
    logger.addHandler(file_handler)

    return logger

def get_api_key(session_key, logger):
    """
    Returns the API key configured by the user from the Splunk enpoint, returns blank when no API key is found
    :param session_key:
    :return: API Key
    """
    # Get configuration file from the helper method defined in utility
    conf = get_conf_file(session_key, 'app_greynoise_settings')
    
    api_key_stanza = conf.get("parameters", {})
    api_key = api_key_stanza.get("api_key", '')
    
    if not api_key:
        message = "API key not found. Please configure the GreyNoise App for Splunk."
        make_error_message(message, session_key, logger)
        raise APIKeyNotFoundError(message)

    return api_key
        
def make_error_message(message, session_key, logger):
    """
    Generates Splunk Error Message
    :param message:
    :param session_key:
    :param filename:
    :return: error message
    """
    try:
        splunk.rest.simpleRequest(
            '/services/messages/new',
            postargs={'name': APP_NAME, 'value': '%s' % (message),
                    'severity': 'error'}, method='POST', sessionKey=session_key
        )
    except Exception:
        logger.error("Error occured while generating error message for Splunk, Error: {}".format(str(traceback.format_exc())))

def get_dict(method):
    """
    Returns dictionary having all the fields as key that may take place while calling the method with None as default value
    """
    dict_hash = {
        'ip': fields.IP_FIELDS,
        'quick': fields.QUICK_FIELDS,
        'query': fields.QUERY_FIELDS,
        'multi': fields.MULTI_FIELDS,
        'filter': fields.FILTER_FIELDS,
        'enrich': fields.ENRICH_FIELDS,
        'riot': fields.RIOT_FIELDS
    }
    return dict_hash.get(method, fields.DEFAULT_FIELDS)

def nested_dict_iter(nested, prefix=''):
    """
    This is a dict inside a list so we assume something like:
        [{port : <port_1>, proto : <proto_1}, {port : <port_2>, proto : <proto_2}]
    We want something like this for Splunk:
        [{port : [<port_1>, <port_2>]},{proto : [<proto_1>, <proto_2>]}]
    :param nested:
    :return: dict
    """
    parsed_dict = {}
    api_response = dict(nested)
    
    def nester_method(api_response, prefix):
        for key, value in list(api_response.items()):
            if isinstance(value, collections.Mapping):  # its a Dictionary
                # This will update the contents of the value dictionary into parsed_dict itself
                nester_method(value, prefix)
            if isinstance(value, list):  # its a list
                _list = value
                for item in _list:
                    if isinstance(item, collections.Mapping):  # its a dict inside a list
                        dict_length = int(len(list(item.keys())))
                        for n in range(0, dict_length):
                            current_key = list(item.keys())[n]
                            if current_key in parsed_dict:
                                parsed_dict[prefix+current_key].append(list(item.values())[n])
                            else:
                                parsed_dict[prefix+current_key] = [list(item.values())[n]]
                    else:
                        parsed_dict[prefix+key] = value
            else:
                parsed_dict[prefix+key] = value
        return parsed_dict
    
    return nester_method(api_response, prefix)

def validate_api_key(api_key, logger=None):
    """
    Validate the API key using the actual lightweight call to the GreyNoise API.
    Returns false only when 401 code is thrown, indicating the unauthorised access.
    :param api_key: 
    :param logger:
    """
    URL = "https://api.greynoise.io/v2/meta/ping"
    HEADER = {
        "key": api_key
    }

    if logger:
        logger.debug("Validating the api key...")

    try:
        response = requests.get(url=URL, headers=HEADER)

        if response.status_code == 429:
            raise RateLimitError()
        if response.status_code >= 400:
            # Processing API response
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                body = response.json()
            else:
                body = response.text
            raise RequestFailure(response.status_code, body)
        return (True, 'API key is valid')
    
    except RateLimitError:
        msg = "RateLimitError occured, please contact the Administrator"
        return (False, 'API key not validated, Error: {}'.format(msg))
    except RequestFailure as e:
        response_code, response_message = e.args
        if response_code == 401:
            return (False, 'Unauthorized. Please check your API key.')
        else:
            # Need to handle this, as splunklib is unable to handle the exception with (400, {'error': 'error_reason'}) format
            msg = "The API call to the GreyNoise platform have been failed with status_code: {} and error: {}".format(response_code, response_message['error'] if isinstance(response_message, dict) else response_message)
            return (False, 'API key not validated, Error: {}'.format(msg))
    except ConnectionError:
        msg = "ConnectionError occured, please check your connection and try again."
        return (False, 'API key not validated, Error: {}'.format(msg))
    except RequestException:
        msg = "An ambiguous exception occured, please try again."
        return (False, 'API key not validated, Error: {}'.format(msg))        
    except Exception as e:
        return (False, 'API key not validated, Error: {}'.format(str(e)))
