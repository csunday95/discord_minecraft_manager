
from typing import List
import sys
import argparse
from helix_api_manager import HelixAPIManager


def main(args: List[str]):
    parser = argparse.ArgumentParser()
    parser.add_argument('client_id')
    parser.add_argument('client_secret')
    parser.add_argument('broadcaster_username')
    parser.add_argument('subscriber_username')
    parse_result = vars(parser.parse_args(args))
    api_manager = HelixAPIManager(
        parse_result['client_id'], 
        parse_result['client_secret']
    )
    broadcaster_uname = parse_result['broadcaster_username']
    sub_uname = parse_result['subscriber_username']
    with api_manager as ham:
        broadcaster_id = ham.get_user_id_by_username(broadcaster_uname)
        subscriber_id = ham.get_user_id_by_username(sub_uname)
        fmt = 'User {} ({}) {} subscribed to Broadcaster {} ({})'
        if ham.is_user_subscribed_by_id(broadcaster_id, subscriber_id):
            sub_status = 'IS'
        else:
            sub_status = 'IS NOT'
        print(fmt.format(
            sub_uname, subscriber_id, sub_status, broadcaster_uname, broadcaster_id
        ))
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
