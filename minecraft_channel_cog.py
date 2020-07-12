from typing import List, Set, Tuple, Optional
import aiohttp
import aiofiles
import aiofiles.os
import json
import os
import asyncio
import shlex
import uuid
import discord
import sys
from discord import Guild, Member, Object
from discord.ext import commands
from discord.ext.commands import Cog, Bot, Context, MinimalHelpCommand, Command


class MinecraftChannelCog(Cog, name='Registration'):
    MOJANG_API_UUID_ENDPOINT = 'https://api.mojang.com/profiles/minecraft'
    MOJANG_API_NAMES_ENDPOINT = 'https://api.mojang.com/user/profiles/{uuid}/names'
    LP_USER_CMD_FMT = 'lp user {} parent {} {}'
    MAIL_SEND_CMD_FMT = 'mail send {who} {what}'

    class MinecraftChannelHelpCommand(MinimalHelpCommand):
        CMD_HELP_FMT = '>>> __{name}__\nUsage: `{usage}`\nDescription: {desc}'
        def __init__(self, monitor_channel: str, mod_channel: str, **options):
            self._monitor_channels = {
                monitor_channel,
                mod_channel
            }
            super().__init__(**options)

        async def command_callback(self, ctx, *, command=None):
            if ctx.channel.name not in self._monitor_channels:
                return
            await super().command_callback(ctx, command=command)

        def get_opening_note(self):
            fmt = '>>> Use `{prefix}{command_name} [command]` for more info on a command.'
            return fmt.format(prefix=self.clean_prefix, command_name='help')

        def add_command_formatting(self, command: Command):
            args = ['[{}]'.format(c) for c in command.clean_params]
            args = ' '.join(args)
            usage = usage='{prefix}{name} {args}'.format(
                prefix=self.clean_prefix,
                name=command.name,
                args=args
            )
            self.paginator.add_line(self.CMD_HELP_FMT.format(
                name=command.name,
                usage=usage,
                desc=command.short_doc
            ))

    def __init__(self, 
                 bot: Bot, 
                 monitor_channel: str, 
                 moderator_channel: str,
                 allowed_roles: Set[str],
                 moderator_roles: Set[str],
                 minecraft_console_send_cmd: str,
                 minecraft_console_sub_cmd: Tuple[str, Tuple[str, str]],
                 managed_role_id: str,
                 whitelist_file_path: str,
                 discord_mc_map_file_path: str):
        self.bot = bot
        self._help_command = MinecraftChannelCog.MinecraftChannelHelpCommand(
            monitor_channel,
            moderator_channel,
            no_category='Other',
            verify_checks=True
        )
        self.bot.help_command = self._help_command
        self._monitor_channel = monitor_channel
        self._moderator_channel = moderator_channel
        self._allowed_roles = allowed_roles
        self._moderator_roles = moderator_roles
        self._minecraft_console_send_cmd = minecraft_console_send_cmd
        self._minecraft_console_sub_cmd = minecraft_console_sub_cmd[0]
        self._managed_role_id = int(managed_role_id)
        self._mc_role_unsub, self._mc_role_sub = minecraft_console_sub_cmd[1]
        self._working_whitelist = None
        self._whitelisted_uuids = None
        self._whitelist_file_path = whitelist_file_path
        self._working_discord_mc_mapping = None
        self._discord_mc_map_file_path = discord_mc_map_file_path
        self._moderator_commands = {
            self.lookupdc,
            self.lookupmc,
            self.warn,
            self.recheck
        }

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

    @commands.Cog.listener()
    async def on_command_error(self, ctx: Context, exception: Exception):
        # if message wasn't from a monitored channel, ignore
        if ctx.channel.name not in {self._monitor_channel, self._moderator_channel}:
            return
        if isinstance(exception, discord.ext.commands.errors.CommandNotFound):
            author_id = str(ctx.author.id)
            fmt = '<@!{}> {}'
            await ctx.channel.send(fmt.format(author_id, exception))
        # TODO: add error logging
        sys.stderr.write(str(exception) + '\n')

    def _has_allowed_role(self, member: Member):
        return any(r.name in self._allowed_roles for r in member.roles)

    def _has_moderator_role(self, member: Member):
        return any(r.name in self._moderator_roles for r in member.roles)
    
    def _is_moderator_command(self, command: Command):
        return command in self._moderator_commands

    def cog_check(self, ctx: Context):
        author = ctx.message.author  # type: Member
        is_moderator = self._has_moderator_role(author)
        is_mod_cmd = self._is_moderator_command(ctx.command)
        # if message is not from monitored channel, ignore
        if ctx.channel.name == self._monitor_channel and not is_mod_cmd:
            return self._has_allowed_role(author) or is_moderator
        return ctx.channel.name == self._moderator_channel and is_moderator

    async def _send_to_minecraft_console(self, text: str):
        """Coroutine to send a command to the minecraft console. The command
        prefix is configuration in config.json.

        Args:
            text (str): the text to append after the configured console send 
            command. Will be quoted.
        """
        # remove some control characters
        text = text.replace('\r', '').replace('\n', '').replace('^','').replace('\\','')
        text = shlex.quote(text)
        # create subprocess to execute command to send to mc console
        handle = await asyncio.create_subprocess_shell(
            self._minecraft_console_send_cmd + ' {}^M'.format(text), 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        # wait for command termination
        stdout, stderr = await handle.communicate()
        # check return code
        return_code = handle.returncode
        if return_code != 0:
            # TODO: error handling here, check stderr/stdout
            return False
        # TODO: log reload here
        return

    async def _add_user_to_whitelist(self, mc_uuid: uuid.UUID, mc_user: str):
        """Add the given user to the whitelist.

        Args:
            mc_uuid (str): the minecraft UUID to add to the whitelist
            mc_user (str): the minecraft username to add
        """
        mc_uuid_str = str(mc_uuid)
        self._working_whitelist.append(
            {'uuid': mc_uuid_str, 'name': mc_user}
        )
        self._whitelisted_uuids.add(mc_uuid)
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                mc_uuid_str, self._mc_role_sub
            )
        )
        await aiofiles.os.rename(self._whitelist_file_path, self._whitelist_file_path + '.bak')
        async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
            await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        await self._send_to_minecraft_console('whitelist reload')

    async def _remove_user_from_whitelist(self, mc_uuid: uuid.UUID):
        """Remvoe the given user from the whitelist based on uuid.

        Args:
            mc_uuid (str): the minecraft user UUID to remove
        """
        # account for whitelist inconsistencies
        mc_uuid_str = str(mc_uuid)
        if mc_uuid not in self._whitelisted_uuids:
            return
        self._working_whitelist = \
            [wl for wl in self._working_whitelist if wl['uuid'] != mc_uuid_str]
        self._whitelisted_uuids.remove(mc_uuid)
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                mc_uuid_str, self._mc_role_unsub
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
        mc_uuid_str, mc_user = wl_entry['uuid'], wl_entry['name']
        mc_uuid = uuid.UUID(mc_uuid_str)
        has_allowed_name = self._has_allowed_role(after)
        if mc_uuid not in self._whitelisted_uuids and has_allowed_name:
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
        mc_uuid_str, _ = wl_entry['uuid'], wl_entry['name']
        await self._remove_user_from_whitelist(uuid.UUID(mc_uuid_str))

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
                mc_uuid_str = wl_entry['uuid']
                mc_uuid = uuid.UUID(mc_uuid_str)
                if disc_id in banned_user_ids:
                    status_changed_list.append((mc_uuid, wl_entry['name'], False, member))
                    continue
                member = guild.get_member(int(disc_id))  # type: Member
                if member is None:
                    print(f'User {disc_id} could not be retrieved')
                    continue  # TODO: log
                # if the uuid is not in the whitelist
                if mc_uuid not in self._whitelisted_uuids:
                    # check if the user has resubbed
                    if self._has_allowed_role(member):
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

    async def _retrieve_mojang_whitelist_entry(self, mc_username: str) -> Tuple[Optional[dict], Optional[str]]:
        """retrieve Mojang registered uuid from API endpoint based on username. 

        Args:
            mc_username (str): the username to look up

        Returns:
            Tuple[Optional[dict], Optional[str]]: A tuple of (whitelist_entry, error) with 
            whitelist_entry being None and error being an error message on failure. Error 
            messages can optionally contain a {username} named format entry.
        """
        async with aiohttp.ClientSession() as session:
            async with session.post(self.MOJANG_API_UUID_ENDPOINT, json=[mc_username]) as r:
                if r.status != 200:
                    return None, 'unable to contact Mojang for usernames.'
                js = await r.json()
        if len(js) < 1:
            return None, '{username} not an existing Minecraft username.'
        mc_uuid = js[0]['id']
        # validate UUID for added safety
        try:
            uuid.UUID(mc_uuid)
        except ValueError:
            return None, 'got an invalid response from Mojang UUID endpoint.'
        mc_name = js[0]['name']
        whitelist_entry = {'uuid': mc_uuid, 'name': mc_name}
        return whitelist_entry, None

    async def _retrieve_current_mojang_username(self, mojang_uuid: uuid.UUID):
        mojang_uuid = mojang_uuid.hex
        async with aiohttp.ClientSession() as session:
            async with session.get(self.MOJANG_API_NAMES_ENDPOINT.format(uuid=mojang_uuid)) as r:
                if r.status == 204:
                    return None, 'not an extant minecraft user UUID.'
                elif r.status != 200:
                    return None, f'unable to contact Mojang for usernames: [{r.status}].'
                js = await r.json()
        return js[0]['name'], None
        

    @commands.command()
    async def register(self, ctx: Context, mc_username: str):
        """Registers a minecraft username to the server whitelist.

        Registers a minecraft username to the discord->mc mapping and minecraft
        whitelist if proper roles are posessed. 

        Args:
            ctx (Context): the context of the register command
            mc_username (str): minecraft username to register
        """
        # get snowflake of author
        author_id = str(ctx.message.author.id)
        # check that author has an allowed role (should always be the case, but to be safe)
        if not self._has_allowed_role(ctx.message.author):
            fmt = '<@!{}> You do not have the necessary roles to bet whitelisted.'
            await ctx.channel.send(fmt.format(author_id))
            return  # TODO: user has somehow illegally joined channel?
        # contact mojang API to get uuid for mc username
        whitelist_entry, err = await self._retrieve_mojang_whitelist_entry(mc_username)
        if whitelist_entry is None:
            fmt = '<@!{discord_id}> ' + err
            await ctx.channel.send(fmt.format(
                discord_id=author_id,
                username=mc_username
            ))
            return
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
        mc_uuid = uuid.UUID(whitelist_entry['uuid'])
        # if the requested whitelist addition is already present, inform and exit
        if mc_uuid in self._whitelisted_uuids:
            fmt = '<@!{}> User {} is already whitelisted.'
            await ctx.channel.send(fmt.format(author_id, mc_username))
            return
        # add new registration to whitelist
        await self._add_user_to_whitelist(mc_uuid, whitelist_entry['name'])
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
        # tell user they are now whitelisted
        fmt = '<@!{}> User {} has been whitelisted.'
        await ctx.channel.send(fmt.format(author_id, mc_username))

    @commands.command()
    async def deregister(self, ctx: Context):
        """Deregister a registered minecraft username.
         
        This allows a new mc usernameto be registered. 
        Also deletes entry in discord -> mc map.

        Args:
            ctx (Context): the discordpy context for this message
        """
        author_id = str(ctx.message.author.id)
        if author_id not in self._working_discord_mc_mapping:
            fmt = '<@!{}> You not currently have a Minecraft account reigstered.'
            await ctx.channel.send(fmt.format(author_id))
            return
        registered_uuid = uuid.UUID(self._working_discord_mc_mapping[author_id]['uuid'])
        await self._remove_user_from_whitelist(registered_uuid)
        # always remove entry from dc mc map
        self._working_discord_mc_mapping.pop(author_id)
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        # demote user to lower mc role
        # remove managed role
        await ctx.message.author.remove_roles(Object(self._managed_role_id), reason='Deregister')
        # reload whitelist
        await self._send_to_minecraft_console('whitelist reload')
        # inform user deregister was successful
        fmt = '<@!{}> Minecraft account successfully deregistered.'
        await ctx.channel.send(fmt.format(author_id))

    @commands.command()
    async def status(self, ctx: Context):
        """Get current minecraft registration status.

        Returns the current minecraft registration status as a message to the
        requesting user.

        Args:
            ctx (Context): Discord message context
        """
        # get author info from context
        author_id = str(ctx.message.author.id)
        # check if author has a registered mc username
        if author_id not in self._working_discord_mc_mapping:
            fmt = '<@!{}> You not currently have a Minecraft account reigstered.'
            await ctx.channel.send(fmt.format(author_id))
            return
        # retrieve mapped whitelist entry
        wl_entry = self._working_discord_mc_mapping[author_id]
        registered_uuid = uuid.UUID(wl_entry['uuid'])
        # send message based on whitelist status
        if registered_uuid in self._whitelisted_uuids:
            fmt = '<@!{}> You have registered {} and are whitelisted.'
            await ctx.channel.send(fmt.format(author_id, wl_entry['name']))
        else:
            fmt = '<@!{}> You have registered {} and but are not whitelisted.'
            await ctx.channel.send(fmt.format(author_id, wl_entry['name']))
    
    @commands.command()
    async def lookupmc(self, ctx: Context, discord_user: str):
        """Get the registered minecraft username of a given discord user.

        Args:
            ctx (Context): the message context of this command invocation
            discord_uder (str): the discord user by name or by snowflake
        """
        if self._working_discord_mc_mapping is None:
            return
        author_id = ctx.message.author.id
        guild = ctx.message.guild  # type: guild 
        mentions = ctx.message.mentions  # type: List[Member]
        # if mention was used, extract member from it
        if len(mentions) > 0:
            member = mentions[0]
        else:
            # try by username first (case sensitive), then fallback to snowflake
            member = guild.get_member_named(discord_user)
        if member is None:
            try:
                discord_user_int = int(discord_user)
                member = guild.get_member(discord_user_int)
            except (TypeError, ValueError):
                # if not a snowflake, ignore and assume user doesn't exist
                pass
        if member is None:
            fmt = '<@!{}> No member with identifer {}.'
            await ctx.channel.send(fmt.format(author_id, discord_user))
            return
        member_id = str(member.id)
        if member_id not in self._working_discord_mc_mapping:
            fmt = '<@!{}> User {} does not have a minecraft username registered.'
            await ctx.channel.send(fmt.format(author_id, discord_user))
            return
        wl_entry = self._working_discord_mc_mapping[member_id]
        fmt = '>>> <@!{}> Discord user {} has minecraft username {}.'
        await ctx.channel.send(
            fmt.format(author_id, discord_user, wl_entry['name'])
        )

    @commands.command()
    async def lookupdc(self, ctx: Context, minecraft_user: str):
        """Get the registered discord username of a given minecraft user.

        Args:
            ctx (Context): the invocation context of this command
            minecraft_user (str): the minecraft username or uuid
        """
        if self._working_discord_mc_mapping is None:
            return
        author_id = ctx.message.author.id
        try:
            # check if requested user is by UUID
            minecraft_user = uuid.UUID(minecraft_user)
        except (ValueError, TypeError):
            pass
        # iterate through dc mc map until we find requested user
        for dc_snowflake, wl_entry in self._working_discord_mc_mapping.items():
            # perform matching check based on argument format
            if isinstance(minecraft_user, uuid.UUID):
                is_matching = uuid.UUID(wl_entry['uuid']) == minecraft_user
            else:
                is_matching = wl_entry['name'] == minecraft_user
            # if we find entry with matching mc user
            if is_matching:
                # get detailed discord member information
                member = ctx.message.guild.get_member(int(dc_snowflake)) # type: Member
                if member is None:
                    # if member can't be retrieved, say so and exit
                    fmt = '>>> <@!{}> Minecraft user {} had Discord snowflake {} but'
                    ' could not be retrieved.'
                    await ctx.channel.send(fmt.format(
                        author_id, minecraft_user, dc_snowflake
                    ))
                    return
                # send requester information about discord user
                fmt = '>>> <@!{}> Minecraft user {} has Discord username {} ({}).'
                await ctx.channel.send(fmt.format(
                    author_id, minecraft_user, member.display_name, member.id
                ))
                return
        # if we did not find a matching user, say so
        fmt = '<@!{}> Minecraft user {} is not registered.'
        await ctx.channel.send(fmt.format(
            author_id, minecraft_user
        ))
        return

    @commands.command()
    async def warn(self, ctx: Context, minecraft_user: str, *warning_text: str):
        """Warn a Minecraft player

        Args:
            ctx (Context): the invocation context of this command
            minecraft_user (str): the minecraft username or uuid
            *warning_text (str): Warning text
        """
        if self._working_discord_mc_mapping is None:
            return
        author_id = ctx.message.author.id
        try:
            # check if requested user is by UUID
            minecraft_user = uuid.UUID(minecraft_user)
        except (ValueError, TypeError):
            pass
        target_member = None  # type: Optional[Member]
        # iterate through dc mc map until we find requested user
        for dc_snowflake, wl_entry in self._working_discord_mc_mapping.items():
            # perform matching check based on argument format
            if isinstance(minecraft_user, uuid.UUID):
                is_matching = uuid.UUID(wl_entry['uuid']) == minecraft_user
            else:
                is_matching = wl_entry['name'] == minecraft_user
            # if we find entry with matching mc user
            if is_matching:
                # get detailed discord member information
                target_member = ctx.message.guild.get_member(int(dc_snowflake))  # type: Member
                if target_member is None:
                    # if member can't be retrieved, say so and exit
                    fmt = '>>> <@!{}> Minecraft user {} had Discord snowflake {} but' \
                          ' could not be retrieved.'
                    await ctx.channel.send(fmt.format(
                        author_id, minecraft_user, dc_snowflake
                    ))
                    return
                break

        if target_member is None:
            # if we did not find a matching user, say so
            fmt = '<@!{}> Minecraft user {} is not registered.'
            await ctx.channel.send(fmt.format(
                author_id, minecraft_user
            ))
        else:
            nice_message = ' '.join(warning_text)

            fmt = 'A moderator has warned you with this message: ' + nice_message
            await self._send_to_minecraft_console(self.MAIL_SEND_CMD_FMT.format(
                who=minecraft_user,
                what=fmt
            ))

            fmt = 'Hey, {who}, you have been warned by a moderator with this message: {what}'
            await target_member.send(fmt.format(
                who='<@{}>'.format(target_member.id),
                what=nice_message
            ))

            fmt = '<@!{author}> Warned {minecraft} ({discord} on Discord) with the message {message}'
            await ctx.channel.send(fmt.format(
                author=author_id,
                minecraft=minecraft_user,
                discord=target_member.id,
                message=nice_message
            ))

    @commands.command()
    async def recheck(self, ctx: Context, old_username: str):
        if self._working_discord_mc_mapping is None:
            return
        author_id = ctx.message.author.id
        try:
            by_uuid = uuid.UUID(old_username)
        except ValueError:
            by_uuid = None
        for _, wl_entry in self._working_discord_mc_mapping.items():
            if by_uuid is None:
                # if no UUID given, check for username match
                if wl_entry['name'].lower() != old_username.lower():
                    continue
            elif by_uuid != uuid.UUID(wl_entry['uuid']):
                # if UUID given, check by UUID
                continue
            old_username = wl_entry['name']
            wl_uuid = uuid.UUID(wl_entry['uuid'])
            new_username, err = await self._retrieve_current_mojang_username(wl_uuid)
            if new_username is None:
                msg = f'<@!{author_id}> ' + err
                await ctx.channel.send(msg)
                return
            uuid_str = str(wl_uuid)
            if old_username.lower() == new_username.lower():
                msg = f'<@!{author_id}> {old_username}\'s ({uuid_str}) username is unchanged.'
                await ctx.channel.send(msg)
                return
            # add new registration to discord mc mapping
            self._working_discord_mc_mapping[str(author_id)] = {'uuid': wl_entry['uuid'], 'name': new_username}
            # make mapping backup
            await aiofiles.os.rename(self._discord_mc_map_file_path, self._discord_mc_map_file_path + '.bak')
            # write out mapping
            async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
                await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
            msg = f'<@!{author_id}> User {old_username} ({uuid_str}) has changed their '
            msg += f'Minecraft username to {new_username}. '
            msg += 'The bot registration has been updated.'
            await ctx.channel.send(msg)
            return
        if by_uuid is None:
            msg = f'<@!{author_id}> No user with Minecraft username {old_username} is registerd.'
        else:
            msg = f'<@!{author_id}> No user with Minecraft UUID {by_uuid} is registerd.'
        await ctx.channel.send(msg)
