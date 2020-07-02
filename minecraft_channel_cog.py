
from typing import Dict, List, Set, Tuple
import aiohttp
import aiofiles
import json
import asyncio
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
                 sub_check_interval: float,
                 whitelist_file_path: str,
                 discord_mc_map_file_path: str):
        self.bot = bot
        self._monitor_channel = monitor_channel
        self._allowed_roles = allowed_roles
        self._minecraft_console_send_cmd = minecraft_console_send_cmd
        self._minecraft_console_sub_cmd = minecraft_console_sub_cmd[0]
        self._managed_role_id = int(managed_role_id)
        self._mc_role_unsub, self._mc_role_sub = minecraft_console_sub_cmd[1]
        self._sub_check_interval = sub_check_interval
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
                self._whitelisted_uuids = set(wl['uuid'] for wl in self._working_whitelist)
        # load discord -> mc mapping from file
        if self._working_discord_mc_mapping is None:
            async with aiofiles.open(self._discord_mc_map_file_path, 'r') as dc_mc_map:
                dc_mc_map_content = await dc_mc_map.read()
                self._working_discord_mc_mapping = json.loads(dc_mc_map_content)  
        # start sub monitoring timer task
        self.bot.loop.create_task(self.check_registered_sub_status())

    async def _send_to_minecraft_console(self, text: str):
        """Coroutine to send a command to the minecraft console. The command
        prefix is configuration in config.json.

        Args:
            text (str): the text to append after the configured console send 
            command. Will be quoted.
        """
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

    async def check_registered_sub_status(self):
        """Periodic task to check if and users have unsubbed or resubbed.
        If they have unsubbed, they will be removed from the whitelist but
        the discord -> mc account relationship will be preserved. If they have
        resubbed, the stored relationship will be restored to the whitelist.
        """
        await self.bot.wait_until_ready()
        while not self.bot.is_closed():
            # list of tuples of (mc_uuid, mc_name, resubbed/unsubbed)
            status_changed_list = []  # type: List[Tuple[str, str, bool, Member]]
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
                            status_changed_list.append((mc_uuid, wl_entry['name'], True, member))
                        continue
                    # if user has none of the allowed roles, they have lost sub
                    if all(r.name not in self._allowed_roles for r in member.roles):
                        status_changed_list.append((mc_uuid, wl_entry['name'], False, member))
            for mc_user_uuid, mc_username, resubbed, member in status_changed_list:
                if resubbed:  # add resubbed users back to whitelist
                    self._working_whitelist.append(
                        {'uuid': mc_user_uuid, 'name': mc_username}
                    )
                    await self._send_to_minecraft_console(
                        self._minecraft_console_sub_cmd.format(
                            mc_user_uuid, self._mc_role_sub
                        )
                    )
                    await member.add_roles(Object(self._managed_role_id), reason='Resub')
                else:  # remove unsubbed users from whitelist
                    self._working_whitelist = \
                        [wl for wl in self._working_whitelist if wl['uuid'] != mc_user_uuid]
                    self._whitelisted_uuids.remove(mc_user_uuid)
                    await self._send_to_minecraft_console(
                        self._minecraft_console_sub_cmd.format(
                            mc_user_uuid, self._mc_role_unsub
                        )
                    )
                    await member.remove_roles(Object(self._managed_role_id), reason='Unsub')
                async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
                    await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
                # TODO: send message in channel to unsubbed user?
            if len(status_changed_list) > 0:
                await self._send_to_minecraft_console('reload whitelist')
            await asyncio.sleep(self._sub_check_interval)

    @commands.command()
    async def register(self, ctx: Context, mc_username: str):
        """Registers a minecraft username to the server whitelist. Also records
        the correspondence between discord and minecraft user.

        Args:
            ctx (Context): [description]
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
                    whitelist_entry = {'uuid': js[0]['id'], 'name': js[0]['name']}
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
        if whitelist_entry['uuid'] in self._whitelisted_uuids:
            fmt = '<@!{}> User {} is already whitelisted.'
            await ctx.channel.send(fmt.format(author_id, mc_username))
            return
        # add new registration to working whitelist
        self._working_whitelist.append(whitelist_entry)
        self._whitelisted_uuids.add(whitelist_entry['uuid'])
        # make whitelist backup
        await aiofiles.os.rename(self._whitelist_file_path, self._whitelist_file_path + '.bak')
        # write out whitelist
        async with aiofiles.open(self._whitelist_file_path, 'w') as whitelist_file:
            await whitelist_file.write(json.dumps(self._working_whitelist, indent=4))
        # add new registration to discord mc mapping
        self._working_discord_mc_mapping[author_id] = whitelist_entry
        # make mapping backup
        await aiofiles.os.rename(self._discord_mc_map_file_path, self._discord_mc_map_file_path + '.bak')
        # write out mapping
        async with aiofiles.open(self._discord_mc_map_file_path, 'w') as dc_mc_map:
            await dc_mc_map.write(json.dumps(self._working_discord_mc_mapping, indent=4))
        # add managed role to use
        await ctx.message.author.add_roles(Object(self._managed_role_id), reason='New Registration')
        # set user to subscriber role in server
        await self._send_to_minecraft_console(
            self._minecraft_console_sub_cmd.format(
                whitelist_entry['uuid'], self._mc_role_sub
            )
        )
        # reload minecraft whitelist in server
        await self._send_to_minecraft_console('whitelist reload')
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