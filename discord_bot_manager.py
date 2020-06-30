
import requests


class DiscordBotManager:
    BOT_SCOPE = 'bot'
    DISCORD_API_ENDPOINT = 'https://discord.com/api/v6'

    def __init__(self, bot_token: str):
        self._bot_token = bot_token

    def get_guild_object(self, guild_id: str):
        resp = requests.get(
            self.DISCORD_API_ENDPOINT + f'/guilds/{guild_id}',
            headers={
                'Authorization': f'Bot {self._bot_token}'
            }
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            return None
        return resp.json()

    def get_guild_channel_list(self, guild_id: str):
        resp = requests.get(
            self.DISCORD_API_ENDPOINT + f'/guilds/{guild_id}/channels',
            headers={
                'Authorization': f'Bot {self._bot_token}'
            }
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            return None
        return resp.json()

    def get_channel_object(self, channel_id: str):
        resp = requests.get(
            self.DISCORD_API_ENDPOINT + f'/channels/{channel_id}',
            headers={
                'Authorization': f'Bot {self._bot_token}'
            }
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            return None
        return resp.json()
    
    def get_channel_message(self, channel_id: str, message_id: str):
        resp = requests.get(
            self.DISCORD_API_ENDPOINT + f'/channels/{channel_id}/messages/{message_id}',
            headers={
                'Authorization': f'Bot {self._bot_token}'
            }
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            return None
        return resp.json()

    def _get_channel_messages(self, channel_id: str, count: int, **params):
        resp = requests.get(
            self.DISCORD_API_ENDPOINT + f'/channels/{channel_id}/messages',
            headers={
                'Authorization': f'Bot {self._bot_token}'
            },
            params={'count': count}.update(params)
        )
        if resp.status_code != requests.status_codes.codes['OK']:
            return None
        return resp.json()

    def get_channel_messages_around(self, channel_id: str, around_id: str, count: int):
        return self._get_channel_messages(channel_id, count, around=around_id)

    def get_channel_messages_before(self, channel_id: str, before_id: str, count: int):
        return self._get_channel_messages(channel_id, count, before=before_id)

    def get_channel_messages_after(self, channel_id: str, after_id: str, count: int):
        return self._get_channel_messages(channel_id, count, after=after_id)

    def get_all_channel_messages_between(self, 
                                         channel_id: str, 
                                         oldest_id: str, 
                                         newest_id: str):
        if int(oldest_id) >= int(newest_id):
            raise ValueError('oldest_id must come before newest_id')
        oldest_id_int = int(oldest_id)
        collected_messages = []
        # add one to newest id so newest message also captured
        oldest_retrieved_id = str(int(newest_id) + 1)
        while int(oldest_retrieved_id) > oldest_id_int:
            retrieved_messages = self.get_channel_messages_before(channel_id, oldest_retrieved_id, 50)
            # messages are sorted oldest to newest
            edge_id = retrieved_messages[-1]['id']
            if edge_id == oldest_retrieved_id:
                # in this case we are at the oldest message in the channel
                break
            oldest_retrieved_id = edge_id
            collected_messages = retrieved_messages + collected_messages
        # since we can get messages from before oldest_id, filter those out
        first_older_index = 0
        for i, msg in enumerate(collected_messages):
            if int(msg['id']) < oldest_id_int:
                first_older_index = i
            else:
                break
        return collected_messages[first_older_index:]
