
from typing import List
import sys
import argparse
import json

from minecraft_validator_sentry import MinecraftValidatorSentry

EXPECTED_CONFIG_PARAMS = {
    'discord_bot_token', 'bot_user_id', 'guild_id', 'monitor_channel_name',
    'whitelist_file_path', 'discord_mc_account_mapping_file_path', 'check_period'
}


def main(args: List[str]):
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file_path', default='config.json')
    result = vars(parser.parse_args(args))
    with open(result['config_file_path']) as config_file:
        config = json.load(config_file)
    if set(config.keys()) != EXPECTED_CONFIG_PARAMS:
        fmt = 'Configuration must contain all of {}'
        print(fmt.format(EXPECTED_CONFIG_PARAMS))
        return 1
    mvs = MinecraftValidatorSentry(**config)
    if not mvs.begin_sentry_session():
        print('Unable to start validator session')
        return 1

    try:
        input('Press any key...')
    except KeyboardInterrupt:
        pass
    mvs.end_session()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
