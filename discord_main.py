
from typing import List
import sys
import argparse

from discord_bot_manager import DiscordBotManager

TEST_CHANNEL_NAME = 'bot-test'


def main(args: List[str]):
    parser = argparse.ArgumentParser()
    parser.add_argument('bot_token')
    result = parser.parse_args(args)
    result = vars(result)
    dbm = DiscordBotManager(result['bot_token'])
    channel_list = dbm.get_guild_channel_list('720043662880538745')
    test_channel_id = None
    for channel in channel_list:
        if channel['type'] != 0:  # ignore non-text channels
            continue
        if channel['name'] == TEST_CHANNEL_NAME:
            test_channel_id = channel['id']
            break
    if test_channel_id is None:
        print('unable to get test channel')
        return 1
    channel_object = dbm.get_channel_object(test_channel_id)
    last_message_id = channel_object['last_message_id']
    messages = dbm.get_all_channel_messages_between(test_channel_id, "0", last_message_id)
    print(messages)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
