#!/usr/bin/env python

# Copyright 2022 Vectra AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import vectra_official as vectra
from datetime import datetime, timedelta, timezone
import logging
import requests
import keyring
import getpass

from typing import Dict, Optional
from itertools import product
from requests.packages.urllib3.exceptions import InsecureRequestWarning


__author__ = "Aurélien Hess"
__copyright__ = "Copyright 20222, Vectra AI"
__credits__ = []
__license__ = "Apache 2.0"
__version__ = "1.0.1"
__maintainer__ = "Aurélien Hess"
__email__ = "ahess@vectra.ai"
__status__ = "Production"


logging.basicConfig(level=logging.INFO)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# If using APIv2 set this
VECTRA_APPLIANCE_URL = None # Example: 'https://vectra.local'

# If using APIv3 set this
VECTRA_PORTAL_URL = None # Example: 'https://000000000000.ew1.portal.vectra.ai'
CLIENT_ID = ''

# Configure Endace endpoint
ENDACE_URL = 'https://endace.example.com'

# If you need to reset credentials, set to True and run
RESET = False

class HTTPException(Exception):
    def __init__(self, response):
        """ 
        Custom exception class to report possible API errors
        The body is contructed by extracting the API error code from the requests.Response object
        """
        try: 
            r = response.json()
            if 'detail' in r:
                detail = r['detail']
            elif 'errors' in r:
                detail = r['errors'][0]['title']
            elif '_meta' in r:
                detail = r['_meta']['message']
            else:
                detail = response.content
        except Exception: 
            detail = response.content
        body = 'Status code: {code} - {detail}'.format(code=str(response.status_code), detail=detail)
        super().__init__(body)


class VectraDetection:

    def __init__(self, detection):
        self.id:int = int(detection['id'])
        self.src:str = detection['src_ip']
        self.destinations:list = self._get_destinations(detection)
        self.first_timestamp:str = datetime.strptime(detection['first_timestamp'], "%Y-%m-%dT%H:%M:%SZ")
        self.last_timestamp:str = datetime.strptime(detection['last_timestamp'], "%Y-%m-%dT%H:%M:%SZ")
        self.note_id:Optional[int] = None

    def _get_destinations(self, detection):
        destinations = set()
        for details in detection['grouped_details']:
            dest_ips = details.get('dst_ips', [])
            destinations.update(dest_ips)
        return list(destinations)


DetectionDict = Dict[int, VectraDetection] 


class VectraAPIWrapper():

    @staticmethod
    def _get_dict_keys_relative_complement(dict1, dict2):
        """
        Function that returns dict of all keys present in dict1 and NOT in dict 2
        """
        result_dict = {}
        for key, value in dict1.items():
            if key not in dict2.keys():
                result_dict[key] = value
        return result_dict

    def __init__(self, vectra_api_client):
        """
        Initialize Vectra client
        :param version: API Version to use - required
        :param url: Vectra Appliance or Portal URL - required
        :param client_id: APIv3 client id, only required for APIv3 - optional
        """
        self.logger = logging.getLogger('VectraClient')
        self.vac = vectra_api_client

    def _get_tagged_detections(self, tag: str) -> DetectionDict:
        """
        Get a dictionnary of all detections that contain given tag
        :param tag: tag to search
        :rtype: DetectionDict
        """
        detections = {}
        r = self.vac.get_all_detections(tags=tag)
        for page in r:
            for detection in page.json().get('results', []):
                if tag in detection['tags']: # for some reason the API does substring matching, so we check
                    detections[detection['id']] = VectraDetection(detection)
        return detections

    def _get_active_detections(self) -> DetectionDict:
        """
        Get a dictionnary of all active detections
        :rtype: DetectionDict
        """
        detections = {}
        r = self.vac.get_all_detections(state='active')
        for page in r:
            for detection in page.json().get('results', []):
                detections[detection['id']] = VectraDetection(detection)
        return detections

    def _get_endace_note(self, detection_id) -> json:
        """
        Get the note ID of the Endace enrichment note
        :param: detection_id
        :rtype: Optional int
        """
        r = self.vac.get_detection_note(detection_id=detection_id)
        for note in r.json():
            if "Endace" in note['note']:
                return note

    def get_all_detections_to_enrich(self) -> DetectionDict:
        active_detections = self._get_active_detections()
        already_tagged_detections = self._get_tagged_detections(tag='Endace')
        return self._get_dict_keys_relative_complement(active_detections, already_tagged_detections)

    def get_all_detections_to_update(self) -> DetectionDict:
        detections = {}
        already_tagged_detections = self._get_tagged_detections(tag='Endace')
        for detection_id, detection in already_tagged_detections.items():
            note = self._get_endace_note(detection_id)
            last_modified = note['date_modified'] if note.get('date_modified') else note['date_created']
            note_last_timestamp = datetime.strptime(last_modified, "%Y-%m-%dT%H:%M:%SZ")
            # Only update if detection was updated more recently than note
            if detection.last_timestamp > note_last_timestamp: 
                detection.note_id=note['id']
                detections[detection_id] = detection
        return detections



class EndaceClient(object):
    def __init__(self, url):
        """
        Initialize Endace client
        :param url: base URL of Endace instance - required
        """
        self.url = url
        self.logger = logging.getLogger('EndaceClient')

    def generate_endace_link(self, vectra_detection)-> str: 
        source_ip = vectra_detection.src
        title = "Vectra{id}".format(id=str(vectra_detection.id))
        destination_ips = vectra_detection.destinations
        # Make the timestamps tz aware (UTC) and convert to milliseconds
        start_ts = int(vectra_detection.first_timestamp.replace(tzinfo=timezone.utc).timestamp()*1000)
        end_ts = int(vectra_detection.last_timestamp.replace(tzinfo=timezone.utc).timestamp()*1000)
        delta_time = end_ts - start_ts
        # If delta time is more than 1 hour, make start time 1 hour before end time
        if delta_time > 3600000:
            start_ts = end_ts - 3600000
        # Add 4 minutes to end time to pick up any event right after this update
        end_ts = end_ts + 240000
        # Add 2 minutes before to start time to avoid a single sample to be all to the left
        start_ts = start_ts - 120000
        # If we have <5 destinations, filter by destination, else only src
        if len (destination_ips) > 5 or len (destination_ips)<1:
            link = "{url}/vision2/v1/pivotintovision/?datasources=tag%3Aall&title={title}&start={start}&end={end}&ip={src}&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress".format(
                    url = self.url,
                    title = title,
                    start = str(start_ts),
                    end = str(end_ts),
                    src = source_ip
                )
        else:
            separator = ',' + source_ip + '%26'
            src_dst_ips_pair = separator.join(destination_ips)
            ip_conversation_string = source_ip + '%26' + src_dst_ips_pair
            link = "{url}/vision2/v1/pivotintovision/?datasources=tag%3Aall&title={title}&start={start}&end={end}&ip_conv={ip_conversations}&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress".format(
                    url = self.url,
                    title = title,
                    start = str(start_ts),
                    end = str(end_ts),
                    ip_conversations = ip_conversation_string
                )
        return link

def version_check(pwd_dict):
    if VECTRA_APPLIANCE_URL:
        api_token = keyring.get_password(service_name = VECTRA_APPLIANCE_URL, username='api_token')
        if not api_token or RESET:
            api_token = getpass.getpass(prompt="Enter your Vectra APIv2 Token: ")
            keyring.set_password(service_name = VECTRA_APPLIANCE_URL, username='api_token', password=api_token)
        pwd_dict['api_token'] = api_token
        return 2
    elif VECTRA_PORTAL_URL:
        secret_key = keyring.get_password(service_name = VECTRA_PORTAL_URL, username='secret_key')
        if not secret_key or RESET:
            secret_key = getpass.getpass(prompt="Enter your Vectra APIv3 Secret Key: ")
            keyring.set_password(service_name = VECTRA_PORTAL_URL, username='secret_key', password=secret_key)
        pwd_dict['secret_key'] = secret_key
        return 3
    else:
        raise ValueError('You need to specify either an appliance or portal URL')

if __name__ == "__main__":
    logger = logging.getLogger()
    # pass a mutable object to the function to get around python not having pointers
    pwd_dict = {'api_token':None, 'secret_key':None}
    version = version_check(pwd_dict)
    if version == 2:
        vaw = VectraAPIWrapper(vectra.VectraClientV2_4(url=VECTRA_APPLIANCE_URL, token=pwd_dict['api_token'], verify=False))
    elif version == 3:
        vaw = VectraAPIWrapper(vectra.VectraClientV3(url=VECTRA_PORTAL_URL, client_id=CLIENT_ID, client_secret=pwd_dict['secret_key'], verify=False))
    ec = EndaceClient(url=ENDACE_URL)
    detections_to_enrich = vaw.get_all_detections_to_enrich()
    detections_to_update = vaw.get_all_detections_to_update()

    for detection_id, detection in detections_to_enrich.items():
        link = ec.generate_endace_link(detection)
        note = "Endace link: [click here]({})".format(link)
        # Create the note
        vaw.vac.set_detection_note(detection_id, note)
        logger.info('Added Endace note/link to detection ID {}'.format(str(detection_id)))
        logger.debug('Link is: {}'.format(link))
        # Set tag for tracking
        vaw.vac.set_detection_tags(detection_id=detection_id, tags=['Endace'], append=True)
        logger.debug('Added Endace tag to detection ID {}'.format(str(detection_id)))
    
    for detection_id, detection in detections_to_update.items():
        logger.info('Detection to update: {}'.format(detection_id))
        link = ec.generate_endace_link(detection)
        note = "Endace link: [click here]({})".format(link)
        # Update the note
        vaw.vac.update_detection_note(detection_id=detection_id, note_id=detection.note_id, note=note)
        logger.info('Updated Endace note/link to detection ID {}'.format(str(detection_id)))
        logger.debug('Link is: {}'.format(link))



