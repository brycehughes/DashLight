#from scapy.all import *
import json
import logging
import requests

#Common devices which we don't care about like router and phones. Used when trying to find the actual 
#identifier for the Dash Button
ignore = {'--','--','--'}

lights= {'--':'Living Room'}
#Local IP
lightsip  = {'192.168.1.167':'Living Room'} 

#Base API information
LEVITON_ROOT = 'https://my.leviton.com/api'
DOMAIN = 'myLeviton'
NOTIFICATION_ID = 'leviton_notification'
NOTIFICATION_TITLE = 'myLeviton Decora Setup'

#Login information
email='--Email--'
password = '--Password--'

#Login
def main():
    session = DecoraWifiSession()
    success = session.login(email,password)
    perms = session.residential_permissions()
    #Get houses
    residences = []
    for permission in perms:
        for res in session.residences(permission['residentialAccountId']):
            residences.append(res)
    #Get switches
    switches = []
    for residence in residences:
        for switch in session.iot_switches(residence['id']):
            #Get all switches (only  1 at this point) 
            switches.append(switch)
            print switch
            

class DecoraWifiSession:
    """This class represents an authorized HTTPS session with the LCS API."""

    def __init__(self):
        """Initialize the session, all content is JSON."""
        self._session = requests.Session()
        self._session.headers.update({'Content-Type': 'application/json'})
        self._user_id = None
        self._email = None
        self._password = None

    def call_api(self, api, payload=None, method='get'):
        """Generic method for calling LCS REST APIs."""
        # Sanity check parameters first...
        if method != 'get' and method != 'post' and method != 'put':
            msg = "Tried DecoraWifiSession.call_api with bad method: %s"
            raise ValueError(msg % method)

        if self._user_id is None and api != '/Person/login':
            raise ValueError('Tried an API call without a login.')

        uri = LEVITON_ROOT + api

        if payload is not None:
            payload_json = json.dumps(payload)
        else:
            payload_json = ''

        response = getattr(self._session, method)(uri, data=payload_json)

        # Unauthorized
        if response.status_code == 401 or response.status_code == 403:
            # Maybe we got logged out? Let's try logging in.
            self.login(self._email, self._password)
            # Retry the request...
            response = getattr(self._session, method)(uri, data=payload_json)

        if response.status_code != 200 and response.status_code != 204:
            _LOGGER.error("myLeviton API call (%s) failed: %s, %s",
                          api, response.status_code, response.body)
            return None

        return json.loads(response.text)

    def login(self, email, password):
        """Login to LCS & save the token for future commands."""
        payload = {
            'email': email,
            'password':password,
            'clientId': 'levdb-echo-proto',  # from myLeviton App
            'registeredVia': 'myLeviton'     # from myLeviton App
        }
        
        #Call Login API
        login_json = self.call_api('/Person/login', payload, 'post')

        if login_json is None:
            return None

        self._session.headers.update({'authorization': login_json['id']})
        self._user_id = login_json['userId']
        self._email = email
        self._password = password

        return login_json

    def logout(self):
        """Logout of LCS."""
        if self._user_id is None:
            _LOGGER.info("Tried to log out, wasn't logged in.")
            return None

        return self.call_api('/Person/logout', None, 'post')

    #Different API Calls which are useful
    
    def residential_permissions(self):
        """Get Leviton residential permissions objects."""
        api = "/Person/%s/residentialPermissions" % self._user_id
        return self.call_api(api, None, 'get')

    def residences(self, residential_account_id):
        """Get Leviton residence objects."""
        api = "/ResidentialAccounts/%s/Residences" % residential_account_id
        return self.call_api(api, None, 'get')

    def iot_switches(self, residence_id):
        """Get Leviton switch objects."""
        api = "/Residences/%s/iotSwitches" % residence_id
        return self.call_api(api, None, 'get')

    def iot_switch_data(self, switch_id):
        """Get Leviton switch attributes for a particular id."""
        return self.call_api("/IotSwitches/%s" % switch_id, None, 'get')

    def iot_switch_update(self, switch_id, attribs):
        """Update a Leviton switch with new attributes."""
        return self.call_api("/IotSwitches/%s" % switch_id, attribs, 'put')

main()
