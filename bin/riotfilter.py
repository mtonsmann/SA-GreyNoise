import sys
import time
import traceback

import app_greynoise_declare
import six
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from splunklib.binding import HTTPError
from greynoise import GreyNoise

import event_generator
from greynoise_exceptions import APIKeyNotFoundError
import utility
import validator

def event_filter(chunk_index, result, records_dict, ip_field, riot_event, method):
    
    api_results = result['response']
    error_flag = True
    # Before yielding events, make the ip lookup dict which will have the following format:
    # {<ip-address>: <API response for that IP address>}
    ip_lookup = {}
    if result['message'] == 'ok':
        error_flag = False
        for event in api_results:
            ip_lookup[event['ip']] = event
    
    for record in records_dict[0]:

        if error_flag:
            # Exception has occured while fetching the noise statuses from API
            if ip_field in record and record[ip_field] != '':
                # These calls have been failed due to API failure, as this event have IP address value, considering them as noise
                if riot_event:
                    event = {
                        'ip': record[ip_field],
                        'error': api_results
                    }
                    yield event_generator.make_invalid_event(method, event, True, record)
            else:
                # Either the record is not having IP field or the value of the IP field is ''
                # send the record as it is as it doesn't have any IP address, after appending all fields
                # Considering this event as non-noisy
                if not riot_event:
                    yield event_generator.make_invalid_event(method, {}, True, record)
        else:
            # Successful execution of the API call
            if ip_field in record and record[ip_field] != '':

                # Check if the IP field is not an iterable to avoid any error while referencing ip in ip_lookup
                if isinstance(record[ip_field], six.string_types) and record[ip_field] in ip_lookup:
                    if ip_lookup[record[ip_field]]['riot'] == riot_event:
                        yield event_generator.make_valid_event(method, ip_lookup[record[ip_field]], True, record)
                else:
                    # Meaning ip is either invalid or not returned by the API, which is case of `multi` method only
                    # Invalid IPs are considered as non-noise
                    if not riot_event:
                        event = {
                            'ip': record[ip_field],
                            'error': 'IP address doesn\'t match the valid IP format'
                        }
                        yield event_generator.make_invalid_event(method, event, True, record)
            else:
                if not riot_event:
                    # Either the record is not having IP field or the value of the IP field is ''
                    # send the record as it is as it doesn't have any IP address, after appending all fields
                    # Considering this event as non-noisy
                    yield event_generator.make_invalid_event(method, {}, True, record)

@Configuration()
class RIOTFilterCommand(EventingCommand):
    """
    Transforming command that returns events according to IP address RIOT (Rule It OuT) status 
    as specified with riot_events parameter, defaults to false.
    Data pulled from: /v2/riot/ip

    **Syntax**::
    `index=firewall | riotfilter ip_field="ip" riot_events="false"

    **Description**::
    The `riotfilter` command returns the events with IP addresses represented by `ip_field` parameter
    according to RIOT status using method :method:`riot` from GreyNoise Python SDK. 
    """

    ip_field = Option(
        doc='''
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events''',
        name='ip_field', require=True
    )

    riot_event = Option(
        doc='''
        **Syntax:** **riot_event=***<true/false>*
        **Description:** Flag specifying whether to return events in RIOT (Rule It OuT) dataset or events not in dataset (default to False)''',
        name='riot_event', require=False, default="False"
    )

    def transform(self, records):

        method = 'riot'

        # Setup logger
        logger = utility.setup_logger(session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)

        # Enter the mechanism only when the Search is complete and all the events are available
        if self.search_results_info and not self.metadata.preview:
            
            EVENTS_PER_CHUNK = 1000
            THREADS = 3
            USE_CACHE = False
            ip_field = self.ip_field
            riot_event = self.riot_event

            logger.info("Started filtering the IP address(es) present in field: {}, with riot_status: {}".format(str(ip_field), str(riot_event)))
            
            try:
                if ip_field:
                    ip_field = ip_field.strip()
                if riot_event:
                    riot_event = riot_event.strip()
                # Validating the given parameters
                try:
                    ip_field = validator.Fieldname(option_name='ip_field').validate(ip_field)
                    riot_event = validator.Boolean(option_name='riot_event').validate(riot_event)
                except ValueError as e:
                    # Validator will throw ValueError with error message when the parameters are not proper
                    logger.error(str(e))
                    self.write_error(str(e))
                    exit(1)

                try:
                    message = ''
                    api_key = utility.get_api_key(self._metadata.searchinfo.session_key, logger=logger)
                except APIKeyNotFoundError as e:
                    message = str(e)
                except HTTPError as e:
                    message = str(e)
            
                if message:
                    self.write_error(message)
                    logger.error("Error occured while retrieving API key, Error: {}".format(message))
                    exit(1)

                # API key validation
                api_key_validation, message = utility.validate_api_key(api_key, logger)
                logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
                if not api_key_validation:
                    logger.info(message)
                    self.write_error(message)
                    exit(1)

                # divide the records in the form of dict of tuples having chunk_index as key
                # {<index>: (<records>, <All the ips in records>)}
                chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger)
                logger.debug("Successfully divided events into chunks")

                # This means there are only 1000 or below IPs to call in the entire bunch of records
                # Use one thread with single thread with caching mechanism enabled for the chunk
                if len(chunk_dict) == 1:
                    logger.info("Less then 1000 distinct IPs are present, optimizing the IP requests call to GreyNoise API...")
                    THREADS = 1
                    USE_CACHE = True

                # Opting timout 120 seconds for the requests
                api_client = GreyNoise(api_key=api_key, timeout=120, use_cache=USE_CACHE, integration_name="Splunk")
                
                # When no records found, batch will return {0:([],[])}
                if len(list(chunk_dict.values())[0][0]) >= 1:
                    for chunk_index, result in event_generator.get_all_events(api_client, method, ip_field, chunk_dict, logger, threads=THREADS):
                        # Pass the collected data to the event filter method
                        for event in event_filter(chunk_index, result, chunk_dict[chunk_index], ip_field, riot_event, method):
                            yield event
                        
                        # Deleting the chunk with the events that are already indexed
                        del chunk_dict[chunk_index]
                        
                    logger.info("Successfully sent all the results to the Splunk")
                else:
                    logger.info("No events found, please increase the search timespan to have more search results.")
                
            except Exception as e:
                logger.info("Exception occured while filtering events, Error: {}".format(traceback.format_exc()))
                self.write_error("Exception occured while filtering the events based on noise status. See greynoise_main.log for more details.")

    def __init__(self):
        super(RIOTFilterCommand, self).__init__()

dispatch(RIOTFilterCommand, sys.argv, sys.stdin, sys.stdout, __name__)



