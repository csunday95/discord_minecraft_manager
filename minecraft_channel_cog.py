
from typing import Dict, List, Set
import aiohttp
import aiofiles
import json
import asyncio
from discord import Guild, Member
from discord.ext import commands
from discord.ext.commands import Cog, Bot, Context


class MinecraftChannelCog(Cog):
    MOJANG_API_UUID_ENDPOINT = 'https://api.mojang.com/profiles/minecraft'

    def __init__(self, 
                 bot: Bot, 
                 monitor_channel: str, 
                 allowed_roles: Set[str],
                 whitelist_reload_cmd: str,
                 sub_check_interval: float,
                 whitelist_file_path: str,
                 discord_mc_map_file_path: str):
        self.bot = bot
        self._monitor_channel = monitor_channel
        self._allowed_roles = allowed_roles
        self._whitelist_reload_cmd = whitelist_reload_cmd
        self._sub_check_interval = sub_check_interval
        self._working_whitelist = None
        self._whitelisted_uuids = None
        self._whitelist_file_path = whitelist_file_path
        self._working_discord_mc_mapping = None
        self._discord_mc_map_file_path = discord_mc_map_file_path

    @commands.Cog.listener()
    async def on_ready(self):
        if self._working_whitelist is None:
            async with aiofiles.open(self._whitelist_file_path, 'r') as whitelist_file:
                whitelist_content = await whitelist_file.read()
                self._working_whitelist = json.loads(whitelist_content)
                self._whitelisted_uuids = set(wl['uuid'] for wl in self._working_whitelist)
        if self._working_discord_mc_mapping is None:
            async with aiofiles.open(self._discord_mc_map_file_path, 'r') as dc_mc_map:
                dc_mc_map_content = await dc_mc_map.read()
                self._working_discord_mc_mapping = json.loads(dc_mc_map_content)  
        self.bot.loop.create_task(self.check_registered_sub_status())

    async def _run_whitelist_reload_cmd(self):
        handle = await asyncio.create_subprocess_shell(
            self._whitelist_reload_cmd, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await handle.communicate()
        print(stdout, stderr, handle.returncode)
        return_code = handle.returncode
        if return_code != 0:
            # TODO: error handling here, check stderr/stdout
            return False
        # TODO: log reload here
        return

    async def check_registered_sub_status(self):
        await self.bot.wait_until_ready()
        while not self.bot.is_closed():
            # list of tuples of (mc_uuid, mc_name, resubbed/unsubbed)
            status_changed_list = []  # type: List[Tuple[str, str, bool]]
            # TODO: hopefully won't exceed 100 guilds
            async for guild in self.bot.fetch_guilds():  # type: Guild
                # have to get complete guild as fetch_guild just gives basic info
                guild = self.bot.get_guild(guild.id)
                for disc_id, wl_entry in self._working_discord_mc_mapping.items():
                    mc_uuid = wl_entry['uuid']
                    member = guild.get_member(int(disc_id))  # type: Member
                    if member is None:
                        continue  # TODO: log
                    # if the uuid is not in the whitelist
                    if mc_uuid not in self._whitelisted_uuids:
                        # check if the user has resubbed
                        if any(r.name in self._allowed_roles for r in member.roles):
                            status_changed_list.append((mc_uuid, wl_entry['name'], True))
                        continue
                    # if user has none of the allowed roles, they have lost sub
                    if all(r.name not in self._allowed_roles for r in member.roles):
                        status_changed_list.append((mc_uuid, wl_entry['name'], False))
            for mc_user_uuid, mc_username, resubbed in status_changed_list:
                if resubbed:  # add resubbed users back to whitelist
                    self._working_whitelist.append(
                        {'uuid': mc_user_uuid, 'name': mc_username}
                    )
                else:  # remove unsubbed users from whitelist
                    self._working_whitelist = \
                        [wl for wl in self._working_whitelist if wl['uuid'] != mc_user_uuid]
                    self._whitelisted_uuids.remove(mc_user_uuid)
                async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
                    await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
                # TODO: send message in channel to unsubbed user?
            if len(status_changed_list) > 0:
                await self._run_whitelist_reload_cmd()
            await asyncio.sleep(self._sub_check_interval)

    @commands.command()
    async def register(self, ctx: Context, mc_username: str):
        if ctx.channel.name != self._monitor_channel:
            return
        author_id = str(ctx.message.author.id)
        if not any(r.name in self._allowed_roles for r in ctx.message.author.roles):
            fmt = '<@!{}> You do not have the necessary roles to bet whitelisted.'
            await ctx.channel.send(fmt.format(author_id))
            return  # TODO: user has somehow illegally joined channel?
        whitelist_entry = None
        async with aiohttp.ClientSession() as session:
            async with session.post(self.MOJANG_API_UUID_ENDPOINT, json=[mc_username]) as r:
                if r.status == 200:
                    js = await r.json()
                    if len(js) < 1:
                        fmt = '<@!{}> {} is not an existing Minecraft username.'
                        await ctx.channel.send(fmt.format(author_id, mc_username))
                        return
                    whitelist_entry = {'uuid': js[0]['id'], 'name': js[0]['name']}
                else:
                    await ctx.channel.send('Got error retrieving id for username {}'.format(mc_username))
        if author_id in self._working_discord_mc_mapping and \
                self._working_discord_mc_mapping[author_id]['uuid'] != whitelist_entry['uuid']:
            fmt = '<@!{}> You have already registered a different Minecraft username.'
            msg = fmt.format(author_id)
            await ctx.channel.send(msg)
            return
        if whitelist_entry is None:
            return
        if whitelist_entry['uuid'] in self._whitelisted_uuids:
            fmt = '<@!{}> User {} is already whitelisted.'
            await ctx.channel.send(fmt.format(author_id, mc_username))
            return
        self._working_whitelist.append(whitelist_entry)
        self._whitelisted_uuids.add(whitelist_entry['uuid'])
        async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
            await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        self._working_discord_mc_mapping[author_id] = whitelist_entry
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        await self._run_whitelist_reload_cmd()
        fmt = '<@!{}> User {} has been whitelisted.'
        await ctx.channel.send(fmt.format(author_id, mc_username))

    @commands.command()
    async def deregister(self, ctx: Context):
        if ctx.channel.name != self._monitor_channel:
            return
        author_id = str(ctx.message.author.id)
        if author_id not in self._working_discord_mc_mapping:
            fmt = '<@!{}> You not currently have a Minecraft account reigstered.'
            await ctx.channel.send(fmt.format(author_id))
            return
        registered_uuid = self._working_discord_mc_mapping[author_id]['uuid']
        # only remove if in whitelist, might not be if e.g. unsubbed
        if registered_uuid in self._whitelisted_uuids:
            # remove deregistered value from whitelist
            self._working_whitelist = \
                [wl for wl in self._working_whitelist if wl['uuid'] != registered_uuid]
            self._whitelisted_uuids.remove(registered_uuid)
            async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
                await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        # always remove entry from dc mc map
        self._working_discord_mc_mapping.pop(author_id)
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        await self._run_whitelist_reload_cmd()
        fmt = '<@!{}> Minecraft account successfully deregistered.'
        await ctx.channel.send(fmt.format(author_id))
