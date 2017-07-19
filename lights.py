#from scapy.all import *
import json
import logging
import requests



ignore = {'fc:f8:ae:4e:a2:4b','b8:27:eb:45:1c:54','00:00:00:00:00:00'}

lights= {'00:07:a6:03:62:db':'Living Room'}
lightsip  = {'192.168.1.167':'Living Room'} 

LEVITON_ROOT = 'https://my.leviton.com/api'
DOMAIN = 'myLeviton'
NOTIFICATION_ID = 'leviton_notification'
NOTIFICATION_TITLE = 'myLeviton Decora Setup'

email='bhugs09@gmail.com'
password = 'Bulldawg7!'
def main():
    session = DecoraWifiSession()
    success = session.login(email,password)
    perms = session.residential_permissions()
    residences = []
    for permission in perms:
        for res in session.residences(permission['residentialAccountId']):
            residences.append(res)

    switches = []
    for residence in residences:
        for switch in session.iot_switches(residence['id']):
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

# class DecoraWifiLight(Light):
#     """Representation of a Decora WiFi switch."""

#     def __init__(self, session, switch):
#         """Initialize the switch."""
#         self._session = session
#         self._id = switch['id']
#         self._switch = switch

#     @property
#     def supported_features(self):
#         """Return supported features."""
#         if self._switch['canSetLevel']:
#             return SUPPORT_BRIGHTNESS | SUPPORT_TRANSITION
#         else:
#             return 0

#     @property
#     def name(self):
#         """Return the display name of this switch."""
#         return self._switch['name']

#     @property
#     def brightness(self):
#         """Return the brightness of the dimmer switch."""
#         return int(self._switch['brightness'] * 255 / 100)

#     @property
#     def is_on(self):
#         """Return true if switch is on."""
#         return self._switch['power'] == 'ON'

#     def turn_on(self, **kwargs):
#         """Instruct the switch to turn on & adjust brightness."""
#         attribs = {'power': 'ON'}

#         if ATTR_BRIGHTNESS in kwargs:
#             min_level = self._switch.get('minLevel', 0)
#             max_level = self._switch.get('maxLevel', 100)
#             brightness = int(kwargs[ATTR_BRIGHTNESS] * max_level / 255)
#             brightness = max(brightness, min_level)
#             attribs['brightness'] = brightness

#         if ATTR_TRANSITION in kwargs:
#             transition = int(kwargs[ATTR_TRANSITION])
#             attribs['fadeOnTime'] = attribs['fadeOffTime'] = transition

#         self._session.iot_switch_update(self._switch['id'], attribs)

#     def turn_off(self, **kwargs):
#         """Instruct the switch to turn off."""
#         self._session.iot_switch_update(self._switch['id'], {'power': 'OFF'})

#     def update(self):
#         """Fetch new state data for this switch."""
#         self._switch = self._session.iot_switch_data(self._id)
