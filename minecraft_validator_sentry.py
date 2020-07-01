
from typing import List
from threading import Thread, Lock
import time
import json
import re
import os
import requests

from discord_bot_manager import DiscordBotManager

ADD_MESSAGE_PATTERN = r'\<@![\d]+\>[\s]+(.*)'


class MinecraftValidatorSentry:
    MOJANG_API_UUID_ENDPOINT = 'https://api.mojang.com/profiles/minecraft'

    def __init__(self, discord_bot_token: str, bot_user_id: str, guild_id: str, 
                 monitor_channel_name: str, whitelist_file_path: str, 
                 discord_mc_account_mapping_file_path: str,check_period: float):
        self._discord_bot_token = discord_bot_token
        self._bot_user_id = bot_user_id
        self._guild_id = guild_id
        self._monitor_channel_name = monitor_channel_name
        self._whitelist_file_path = whitelist_file_path
        self._discord_mc_account_mapping_file_path = discord_mc_account_mapping_file_path
        self._whitelist_lock = Lock()
        self._check_period = check_period
        self._monitor_channel_id = None  # type: str
        self._is_validating = False
        self._discord_join_thread = None  # type: Thread
        self._discord_bot_manager = None  # type: DiscordBotManager

    def _add_to_whitelist_from_messages(self, messages: List[dict]):
        users_to_add = []  # list of tuples of discord user id, mc username
        for message in messages:
            # check if bot is mentioned
            if self._bot_user_id not in [m['id'] for m in message['mentions']]:
                continue
            message_match = re.match(ADD_MESSAGE_PATTERN, message['content'])
            # TODO: ignore messages not following the format, later send error resp to user?
            if message_match is None:
                continue
            users_to_add.append((message, message_match.group(1)))
        new_whitelist_entries = []
        while len(users_to_add) > 0:
            first_ten, users_to_add = users_to_add[:10], users_to_add[10:]
            resp = requests.post(
                self.MOJANG_API_UUID_ENDPOINT, 
                json=[t[1] for t in first_ten]
            )
            if resp.status_code != requests.status_codes.codes['OK']:
                return False  # if unable to contact mojang
            resp = resp.json()
            found_unames = {r['name']: r['id'] for r in resp}
            for discord_message, mc_username in first_ten:
                if mc_username in found_unames:
                    new_whitelist_entries.append(({
                        'uuid': found_unames[mc_username],
                        'name': mc_username
                    }, discord_message))
                else:
                    new_whitelist_entries.append((None, discord_message))
        with self._whitelist_lock:
            # read mc whitelist file
            with open(self._whitelist_file_path, 'r') as whitelist_file:
                current_whitelist = json.loads(whitelist_file.read())
            # read discord mc account mapping file
            if os.path.isfile(self._discord_mc_account_mapping_file_path):
                with open(self._discord_mc_account_mapping_file_path, 'r') as map_file:
                    current_disc_mc_map = json.loads(map_file.read())
            else:
                with open(self._discord_mc_account_mapping_file_path, 'w') as map_file:
                    map_file.write('{}\n')
                    current_disc_mc_map = dict()
            for whitelist_entry, discord_message in new_whitelist_entries:
                discord_user_id = discord_message['author']['id']
                minecraft_account_name = whitelist_entry['name']
                if whitelist_entry is None:
                    self._discord_bot_manager.send_message_to_channel(
                        self._monitor_channel_id,
                        f'<@!{discord_user_id}> Minecraft account {minecraft_account_name} does not exist.',
                        [discord_user_id]
                    )  # TODO: add logging of failures
                    continue
                if discord_user_id in current_disc_mc_map:
                    registered_acct = current_disc_mc_map[discord_user_id]
                    self._discord_bot_manager.send_message_to_channel(
                        self._monitor_channel_id,
                        f'<@!{discord_user_id}> You have already registered Minecraft account {registered_acct}.',
                        [discord_user_id]
                    )  # TODO: add logging of failures
                    continue
                current_disc_mc_map[discord_user_id] = whitelist_entry['uuid']
                current_whitelist.append(whitelist_entry)
                self._discord_bot_manager.send_message_to_channel(
                    self._monitor_channel_id,
                    f'<@!{discord_user_id}> Your username {minecraft_account_name} has been whitelisted.',
                    [discord_user_id]
                )
            with open(self._whitelist_file_path, 'w') as whitelist_file:
                whitelist_file.write(json.dumps(current_whitelist, indent=4))
            with open(self._discord_mc_account_mapping_file_path, 'w') as map_file:
                map_file.write(json.dumps(current_disc_mc_map, indent=4))
        return True

    def _discord_join_channel_monitor_callback(self):
        # TODO: for now 0, but prob load from file
        last_checked_id = 0
        while self._is_validating:
            start_time = time.perf_counter()
            channel_object = \
                 self._discord_bot_manager.get_channel_object(self._monitor_channel_id)
            last_message_id = channel_object['last_message_id']
            # if we're up to date, don't bother retrieving messages
            if last_message_id == last_checked_id:
                while time.perf_counter() - start_time < self._check_period and self._is_validating:
                    time.sleep(0.2)
                continue
            unchecked_messages = self._discord_bot_manager.get_all_channel_messages_between(
                self._monitor_channel_id, last_checked_id, last_message_id
            )
            self._add_to_whitelist_from_messages(unchecked_messages)
            last_checked_id = last_message_id
            while time.perf_counter() - start_time < self._check_period and self._is_validating:
                time.sleep(0.2)
    
    def _extract_monitor_channel_id(self):
        channels = self._discord_bot_manager.get_guild_channel_list(
            self._guild_id
        )
        if channels is None:
            return None
        for channel in channels:
            if channel['type'] != 0:
                continue
            if channel['name'] == self._monitor_channel_name:
                return channel['id']
        return None

    def begin_sentry_session(self):
        self._discord_join_thread = Thread(
            target=self._discord_join_channel_monitor_callback
        )
        self._discord_bot_manager = DiscordBotManager(
            self._discord_bot_token
        )
        channel_id = self._extract_monitor_channel_id()
        if channel_id is None:
            return False
        self._monitor_channel_id = channel_id
        self._is_validating = True
        self._discord_join_thread.start()
        return True

    def run_terminal(self):
        pass

    def end_session(self):
        self._is_validating = False
        self._discord_join_thread.join()
        self._discord_bot_manager = None
