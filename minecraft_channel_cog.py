
from typing import Dict, List, Set, Tuple
import aiohttp
import aiofiles
import aiofiles.os
import json
import asyncio
import shlex
import uuid
import discord
from discord import Guild, Member, Object
from discord.ext import commands
from discord.ext.commands import Cog, Bot, Context


class MinecraftChannelCog(Cog):
    MOJANG_API_UUID_ENDPOINT = 'https://api.mojang.com/profiles/minecraft'
    LP_USER_CMD_FMT = 'lp user {} parent {} {}'

    def __init__(self, 
                 bot: Bot, 
                 monitor_channel: str, 
                 allowed_roles: Set[str],
                 minecraft_console_send_cmd: str,
                 minecraft_console_sub_cmd: Tuple[str, Tuple[str, str]],
                 managed_role_id: str,
                 whitelist_file_path: str,
                 discord_mc_map_file_path: str):
        self.bot = bot
        self._monitor_channel = monitor_channel
        self._allowed_roles = allowed_roles
        self._minecraft_console_send_cmd = minecraft_console_send_cmd
        self._minecraft_console_sub_cmd = minecraft_console_sub_cmd[0]
        self._managed_role_id = int(managed_role_id)
        self._mc_role_unsub, self._mc_role_sub = minecraft_console_sub_cmd[1]
        self._working_whitelist = None
        self._whitelisted_uuids = None
        self._whitelist_file_path = whitelist_file_path
        self._working_discord_mc_mapping = None
        self._discord_mc_map_file_path = discord_mc_map_file_path

    @commands.Cog.listener()
    async def on_ready(self):
        """Startup code that runs once the bot is ready. 
        """
        # load whitelist from file
        if self._working_whitelist is None:
            async with aiofiles.open(self._whitelist_file_path, 'r') as whitelist_file:
                whitelist_content = await whitelist_file.read()
                self._working_whitelist = json.loads(whitelist_content)
                self._whitelisted_uuids = set(
                    uuid.UUID(wl['uuid']) for wl in self._working_whitelist
                )
        # load discord -> mc mapping from file
        if self._working_discord_mc_mapping is None:
            async with aiofiles.open(self._discord_mc_map_file_path, 'r') as dc_mc_map:
                dc_mc_map_content = await dc_mc_map.read()
                self._working_discord_mc_mapping = json.loads(dc_mc_map_content)  
        # start sub monitoring timer task
        await self._check_registered_sub_status()

    async def _send_to_minecraft_console(self, text: str):
        """Coroutine to send a command to the minecraft console. The command
        prefix is configuration in config.json.

        Args:
            text (str): the text to append after the configured console send 
            command. Will be quoted.
        """
        text = shlex.quote(text)
        # create subprocess to execute command to send to mc console
        handle = await asyncio.create_subprocess_shell(
            self._minecraft_console_send_cmd + ' "{}"'.format(text), 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        # wait for command termination
        stdout, stderr = await handle.communicate()
        print(stdout, stderr, handle.returncode)
        # check return code
        return_code = handle.returncode
        if return_code != 0:
            # TODO: error handling here, check stderr/stdout
            return False
        # TODO: log reload here
        return

    async def _add_user_to_whitelist(self, mc_uuid: str, mc_user: str):
        """Add the given user to the whitelist.

        Args:
            mc_uuid (str): the minecraft UUID to add to the whitelist
            mc_user (str): the minecraft username to add
        """
        self._working_whitelist.append(
            {'uuid': mc_uuid, 'name': mc_user}
        )
        self._whitelisted_uuids.add(uuid.UUID(mc_uuid))
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                mc_uuid, self._mc_role_sub
            )
        )
        await aiofiles.os.rename(self._whitelist_file_path, self._whitelist_file_path + '.bak')
        async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
            await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        await self._send_to_minecraft_console('whitelist reload')

    async def _remove_user_from_whitelist(self, mc_uuid: str):
        """Remvoe the given user from the whitelist based on uuid.

        Args:
            mc_uuid (str): the minecraft user UUID to remove
        """
        # account for whitelist inconsistencies
        parsed_mc_uuid = uuid.UUID(mc_uuid)
        if parsed_mc_uuid not in self._whitelisted_uuids:
            return
        self._working_whitelist = \
            [wl for wl in self._working_whitelist if wl['uuid'] != mc_uuid]
        self._whitelisted_uuids.remove(parsed_mc_uuid)
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                mc_uuid, self._mc_role_unsub
            )
        )
        await aiofiles.os.rename(self._whitelist_file_path, self._whitelist_file_path + '.bak')
        async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
            await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        await self._send_to_minecraft_console('whitelist reload')

    @commands.Cog.listener()
    async def on_member_update(self, before: Member, after: Member):
        """Handle member update events, specifically update whitelist
        based on role changes.

        Args:[description]
            before (Member): pevious member data
            after (Member): new member data
        """
        # ignore if we aren't done w/ initializtion
        if self._working_discord_mc_mapping is None:
            return
        # ignore if roles haven't changed
        before_role_set = set(r.id for r in before.roles)
        after_role_set = set(r.id for r in after.roles)
        if set(before_role_set) == set(after_role_set):
            return
        # if the only change is adding the managed role, ignore
        if (after_role_set ^ before_role_set) == set([self._managed_role_id]):
            return
        member_id = str(before.id)
        if member_id not in self._working_discord_mc_mapping:
            return
        wl_entry = self._working_discord_mc_mapping[member_id]
        mc_uuid, mc_user = wl_entry['uuid'], wl_entry['name']
        has_allowed_name = any(r.name in self._allowed_roles for r in after.roles)
        if uuid.UUID(mc_uuid) not in self._whitelisted_uuids and has_allowed_name:
            await self._add_user_to_whitelist(mc_uuid, mc_user)
            try:
                await after.add_roles(Object(self._managed_role_id), reason='Resub')
            except discord.errors.NotFound:
                print('Role not found')
                return
        elif not has_allowed_name:
            await self._remove_user_from_whitelist(mc_uuid)
            try:
                await after.remove_roles(Object(self._managed_role_id), reason='Unsub')
            except discord.errors.NotFound:
                print('Role not found')
                return

    @commands.Cog.listener()
    async def on_member_ban(self, guild: Guild, user: Member):
        if self._working_discord_mc_mapping is None:
            return
        member_id = str(user.id)
        if member_id not in self._working_discord_mc_mapping:
            return
        wl_entry = self._working_discord_mc_mapping[member_id]
        mc_uuid, _ = wl_entry['uuid'], wl_entry['name']
        await self._remove_user_from_whitelist(mc_uuid)

    async def _check_registered_sub_status(self):
        """Periodic task to check if and users have unsubbed or resubbed.
        If they have unsubbed, they will be removed from the whitelist but
        the discord -> mc account relationship will be preserved. If they have
        resubbed, the stored relationship will be restored to the whitelist.
        """
        await self.bot.wait_until_ready()
        # list of tuples of (mc_uuid, mc_name, resubbed/unsubbed)
        status_changed_list = []  # type: List[Tuple[str, str, bool, Member]]
        # TODO: hopefully won't exceed 100 guilds
        async for guild in self.bot.fetch_guilds():  # type: Guild
            # have to get complete guild as fetch_guild just gives basic info
            guild = self.bot.get_guild(guild.id)
            if guild is None:
                print('Unable to retrieve guild')
                return  # TODO: log
            ban_list = await guild.bans()
            banned_user_ids = set(str(be[1].id) for be in ban_list)
            for disc_id, wl_entry in self._working_discord_mc_mapping.items():
                mc_uuid = wl_entry['uuid']
                if disc_id in banned_user_ids:
                    status_changed_list.append((mc_uuid, wl_entry['name'], False, member))
                    continue
                member = guild.get_member(int(disc_id))  # type: Member
                if member is None:
                    print(f'User {disc_id} could not be retrieved')
                    continue  # TODO: log
                # if the uuid is not in the whitelist
                if uuid.UUID(mc_uuid) not in self._whitelisted_uuids:
                    # check if the user has resubbed
                    if any(r.name in self._allowed_roles for r in member.roles):
                        status_changed_list.append((mc_uuid, wl_entry['name'], True, member))
                    continue
                # if user has none of the allowed roles, they have lost sub
                if all(r.name not in self._allowed_roles for r in member.roles):
                    status_changed_list.append((mc_uuid, wl_entry['name'], False, member))
        for mc_user_uuid, mc_username, resubbed, member in status_changed_list:
            if resubbed:  # add resubbed users back to whitelist
                await self._add_user_to_whitelist(mc_user_uuid, mc_username)
                await member.add_roles(Object(self._managed_role_id), reason='Resub')
            else:
                removal_reason = 'Banned' if str(member.id) in banned_user_ids else 'Unsub'
                await self._remove_user_from_whitelist(mc_user_uuid)
                await member.remove_roles(Object(self._managed_role_id), reason=removal_reason)
            # TODO: send message in channel to unsubbed user?

    @commands.command()
    async def register(self, ctx: Context, mc_username: str):
        """Registers a minecraft username to the server whitelist. Also records
        the correspondence between discord and minecraft user.

        Args:
            ctx (Context): the context of the register command
            mc_username (str): minecraft username to register
        """
        # if message is not from monitored channel, ignore
        if ctx.channel.name != self._monitor_channel:
            return
        # get snowflake of author
        author_id = str(ctx.message.author.id)
        # check that author has an allowed role (should always be the case, but to be safe)
        if not any(r.name in self._allowed_roles for r in ctx.message.author.roles):
            fmt = '<@!{}> You do not have the necessary roles to bet whitelisted.'
            await ctx.channel.send(fmt.format(author_id))
            return  # TODO: user has somehow illegally joined channel?
        # contact mojang API to get uuid for mc username
        whitelist_entry = None
        async with aiohttp.ClientSession() as session:
            async with session.post(self.MOJANG_API_UUID_ENDPOINT, json=[mc_username]) as r:
                if r.status == 200:
                    js = await r.json()
                    if len(js) < 1:
                        fmt = '<@!{}> {} is not an existing Minecraft username.'
                        await ctx.channel.send(fmt.format(author_id, mc_username))
                        return
                    mc_uuid = js[0]['id']
                    # validate UUID for added safety
                    try:
                        uuid.UUID(mc_uuid)
                    except ValueError:
                        fmt = '<@!{}> Got an invalid response from Mojang UUID endpoint.'
                        await ctx.channel.send(fmt.format(author_id, mc_username))
                        return
                    mc_name = js[0]['name']
                    whitelist_entry = {'uuid': mc_uuid, 'name': mc_name}
                else:
                    await ctx.channel.send('Got error retrieving id for username {}'.format(mc_username))
        # if discord user has already reigstered a different MC username
        if author_id in self._working_discord_mc_mapping and \
                self._working_discord_mc_mapping[author_id]['uuid'] != whitelist_entry['uuid']:
            fmt = '<@!{}> You have already registered a different Minecraft username.'
            msg = fmt.format(author_id)
            # inform them as such and exit
            await ctx.channel.send(msg)
            return
        # if we were unable to retrieve a whitelist entry
        if whitelist_entry is None:
            return
        # if the requested whitelist addition is already present, inform and exit
        if uuid.UUID(whitelist_entry['uuid']) in self._whitelisted_uuids:
            fmt = '<@!{}> User {} is already whitelisted.'
            await ctx.channel.send(fmt.format(author_id, mc_username))
            return
        # add new registration to whitelist
        await self._add_user_to_whitelist(whitelist_entry['uuid'], whitelist_entry['name'])
        # add new registration to discord mc mapping
        self._working_discord_mc_mapping[author_id] = whitelist_entry
        # make mapping backup
        await aiofiles.os.rename(self._discord_mc_map_file_path, self._discord_mc_map_file_path + '.bak')
        # write out mapping
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        # add managed role to use
        try:
            await ctx.message.author.add_roles(Object(self._managed_role_id), reason='New Registration')
        except discord.errors.NotFound:
            print('role not found')
            return  # TODO: log
        # set user to subscriber role in server
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                whitelist_entry['uuid'], self._mc_role_sub
            )
        )
        # tell user they are now whitelisted
        fmt = '<@!{}> User {} has been whitelisted.'
        await ctx.channel.send(fmt.format(author_id, mc_username))

    @commands.command()
    async def deregister(self, ctx: Context):
        """Deregister a user from the minecraft whitelist, allowing a new mc username
        to be registered. Also deletes entry in discord -> mc map.

        Args:
            ctx (Context): the discordpy context for this message
        """
        if ctx.channel.name != self._monitor_channel:
            return
        author_id = str(ctx.message.author.id)
        if author_id not in self._working_discord_mc_mapping:
            fmt = '<@!{}> You not currently have a Minecraft account reigstered.'
            await ctx.channel.send(fmt.format(author_id))
            return
        registered_uuid = self._working_discord_mc_mapping[author_id]['uuid']
        await self._remove_user_from_whitelist(registered_uuid)
        # always remove entry from dc mc map
        self._working_discord_mc_mapping.pop(author_id)
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        # demote user to lower mc role
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                registered_uuid, self._mc_role_unsub
            )
        )
        # remove managed role
        await ctx.message.author.remove_roles(Object(self._managed_role_id), reason='Deregister')
        # reload whitelist
        await self._send_to_minecraft_console('whitelist reload')
        # inform user deregister was successful
        fmt = '<@!{}> Minecraft account successfully deregistered.'
        await ctx.channel.send(fmt.format(author_id))
