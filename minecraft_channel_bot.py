import discord 
from discord.ext.commands import Bot, Context
from discord import Message
import sys
import os
import argparse
import json
import asyncio
from threading import Thread

from minecraft_channel_cog import MinecraftChannelCog

EXPECTED_CONFIG_PARAMS = {
    'bot_token', 'bot_prefix', 'monitor_channel', 'moderator_channel', 
    'allowed_roles', 'moderator_roles', 'minecraft_console_send_cmd',
    'minecraft_console_sub_cmd', 'managed_role_id', 'whitelist_file_path', 
    'disc_mc_map_file_path'
}


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'config_file_path', 
        default='config.json',
        nargs='?'
    )
    result = vars(parser.parse_args())
    config_file_path = result['config_file_path']
    if not os.path.isfile(config_file_path):
        print(f'Config file {config_file_path} does not exist')
        return 1
    with open(config_file_path, 'r') as config_file:
        config = json.load(config_file)
    if set(config.keys()) != EXPECTED_CONFIG_PARAMS:
        fmt = 'config elements must consist of {}'
        print(fmt.format(EXPECTED_CONFIG_PARAMS))
        return 1

    if not os.path.isfile(config['whitelist_file_path']):
        fmt = 'Whitelist file {} does not exist'
        print(fmt.format(config['whitelist_file_path']))
        return 1
    if not os.path.isfile(config['disc_mc_map_file_path']):
        with open(config['disc_mc_map_file_path'], 'w') as dc_mc_map:
            json.dump(dict(), dc_mc_map)

    bot = Bot(config['bot_prefix'], fetch_offline_members=True)
    mcc = MinecraftChannelCog(
        bot, 
        config['monitor_channel'],
        config['moderator_channel'],
        set(config['allowed_roles']),
        set(config['moderator_roles']),
        config['minecraft_console_send_cmd'],
        config['minecraft_console_sub_cmd'],
        config['managed_role_id'],
        config['whitelist_file_path'],
        config['disc_mc_map_file_path']
    )
    bot.add_cog(mcc)
    bot.run(config['bot_token'])
    print('bot exiting cleanly')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
