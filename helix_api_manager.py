
from typing import Optional, List
import requests


class HelixAPIManager:
    TWITCH_ID_URL = 'https://id.twitch.tv/oauth2/'
    TWITCH_API_URL = 'https://api.twitch.tv/helix/'
    REQUIRED_API_SCOPES = [
        'channel:read:subscriptions', 
        'user:read:email',
        'user:read:broadcast'
    ]

    def __init__(self, client_id: str, client_secret: str) -> None:
        self._client_id, self._client_secret = client_id, client_secret
        self._auth_token = None

    def __enter__(self):
        resp = requests.post(
            self.TWITCH_ID_URL + 'token',
            params={
                'client_id': self._client_id, 
                'client_secret': self._client_secret, 
                'grant_type': 'client_credentials',
                'scope': ' '.join(self.REQUIRED_API_SCOPES)
            }
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            raise RuntimeError('Unable to acquire token: {}'.format(resp.text))
        resp = resp.json()
        self._auth_token = resp['access_token']
        return self

    def __exit__(self, type, value, traceback):
        revoke_resp = requests.post(self.TWITCH_ID_URL + 'revoke', 
            params={'client_id': self._client_id, 'token': self._auth_token}
        )
    
    def get_user_id_by_username(self, username: str) -> Optional[str]:
        if self._auth_token is None:
            raise RuntimeError('API Manager has not received an auth token')
        resp = requests.get(
            self.TWITCH_API_URL + 'users',
            headers={
                'Client-ID': self._client_id,
                'Authorization': f'Bearer {self._auth_token}'
            },
            params={'login': username}
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            raise RuntimeError('Got Error response from twitch: {}'.format(resp.status_code))
        user_info = resp.json()['data'][0]
        return user_info['id']

    def is_user_subscribed_by_id(self, broadcaster_id: str, subscriber_id: str) -> bool:
        resp = requests.get(
            self.TWITCH_API_URL + 'subscriptions',
            headers={
                'Client-ID': self._client_id,
                'Authorization': f'Bearer {self._auth_token}'
            },
            params={'broadcaster_id': broadcaster_id, 'user_id': subscriber_id}
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            raise RuntimeError('Got Error response from twitch: {}'.format(resp.status_code))
        user_sub_data = resp.json()['data']
        return len(user_sub_data) > 0
