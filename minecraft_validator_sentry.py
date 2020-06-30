
from threading import Thread
from discord_bot_manager import DiscordBotManager

from discord_bot_manager import DiscordBotManager


class MinecraftValidatorSentry:
    def __init__(self, discord_bot_token: str, guild_id: str, monitor_channel_name: str):
        self._discord_bot_token = discord_bot_token
        self._guild_id = guild_id
        self._monitor_channel_name = monitor_channel_name
        self._monitor_channel_id = None  # type: str
        self._is_validating = False
        self._validation_thread = None  # type: Thread
        self._discord_bot_manager = None  # type: DiscordBotManager

    def _validation_session_callback(self):
        last_checked_id = None
        while self._is_validating:
            channel_object = \
                 self._discord_bot_manager.get_channel_object(self._monitor_channel_id)
            last_message_id = channel_object['last_message_id']
            if last_message_id == last_checked_id:
                continue
            new_messages = []
            last_messages = self._discord_bot_manager.get_channel_messages_around(
                self._monitor_channel_id, last_message_id, 50
            )
    
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

    def begin_session(self):
        self._validation_thread = Thread(
            target=self._validation_session_callback
        )
        self._discord_bot_manager = DiscordBotManager(
            self._discord_bot_token
        )
        channel_id = self._extract_monitor_channel_id()
        if channel_id is None:
            return False
        self._monitor_channel_id = channel_id
        self._is_validating = True
        self._validation_thread.start()
        return True

    def end_session(self):
        self._is_validating = False
        self._validation_thread.join()
        self._discord_bot_manager = None
