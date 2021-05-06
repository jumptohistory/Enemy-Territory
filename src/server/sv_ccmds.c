/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company. 

This file is part of the Wolfenstein: Enemy Territory GPL Source Code (Wolf ET Source Code).  

Wolf ET Source Code is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Wolf ET Source Code is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wolf ET Source Code.  If not, see <http://www.gnu.org/licenses/>.

In addition, the Wolf: ET Source Code is also subject to certain additional terms. You should have received a copy of these additional terms immediately following the terms and conditions of the GNU General Public License which accompanied the Wolf ET Source Code.  If not, please request a copy in writing from id Software at the address below.

If you have questions concerning this license or the applicable additional terms, you may contact in writing id Software LLC, c/o ZeniMax Media Inc., Suite 120, Rockville, Maryland 20850 USA.

===========================================================================
*/


#include "server.h"

/*
===============================================================================

OPERATOR CONSOLE ONLY COMMANDS

These commands can only be entered from stdin or by a remote operator datagram
===============================================================================
*/


/*
==================
SV_GetPlayerByName

Returns the player with name from Cmd_Argv(1)
==================
*/
static client_t *SV_GetPlayerByName( void ) {
	client_t    *cl;
	int i;
	char        *s;
	char cleanName[64];

	// make sure server is running
	if ( !com_sv_running->integer ) {
		return NULL;
	}

	if ( Cmd_Argc() < 2 ) {
		Com_Printf( "No player specified.\n" );
		return NULL;
	}

	s = Cmd_Argv( 1 );

	// check for a name match
	for ( i = 0, cl = svs.clients ; i < sv_maxclients->integer ; i++,cl++ ) {
		if ( cl->state <= CS_ZOMBIE ) {
			continue;
		}
		if ( !Q_stricmp( cl->name, s ) ) {
			return cl;
		}

		Q_strncpyz( cleanName, cl->name, sizeof( cleanName ) );
		Q_CleanStr( cleanName );
		if ( !Q_stricmp( cleanName, s ) ) {
			return cl;
		}
	}

	Com_Printf( "Player %s is not on the server\n", s );

	return NULL;
}

/*
==================
SV_GetPlayerByNum

Returns the player with idnum from Cmd_Argv(1)
==================
*/
// fretn unused
#if 1
static client_t *SV_GetPlayerByNum( void ) {
	client_t    *cl;
	//int i;
	int idnum;
	char        *s;
	char *ep;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		return NULL;
	}

	if ( Cmd_Argc() < 2 ) {
		Com_Printf( "No player specified.\n" );
		return NULL;
	}

	s = Cmd_Argv( 1 );

	idnum = strtol( s, &ep, 10 );
	if ( ep == s || *ep ) {
		Com_Printf( "Bad slot number: %s\n", s );
		return NULL;
	}
	if ( idnum < 0 || idnum >= sv_maxclients->integer ) {
		Com_Printf( "Bad client slot: %i\n", idnum );
		return NULL;
	}

	cl = &svs.clients[idnum];
	if ( cl->state <= CS_ZOMBIE ) {
		Com_Printf( "Client %i is not active\n", idnum );
		return NULL;
	}
	return cl;

	return NULL;
}
#endif
//=========================================================


/*
==================
SV_Map_f

Restart the server on a different map
==================
*/
static void SV_Map_f( void ) {
	char        *cmd;
	char        *map;
	char smapname[MAX_QPATH];
	char mapname[MAX_QPATH];
	qboolean killBots, cheat, buildScript;
	char expanded[MAX_QPATH];
	int savegameTime = -1;
	char        *cl_profileStr = Cvar_VariableString( "cl_profile" );

	map = Cmd_Argv( 1 );
	if ( !map ) {
		return;
	}

	if ( !com_gameInfo.spEnabled ) {
		if ( !Q_stricmp( Cmd_Argv( 0 ), "spdevmap" ) || !Q_stricmp( Cmd_Argv( 0 ), "spmap" ) ) {
			Com_Printf( "Single Player is not enabled.\n" );
			return;
		}
	}

	buildScript = Cvar_VariableIntegerValue( "com_buildScript" );

	if ( SV_GameIsSinglePlayer() ) {
		if ( !buildScript && sv_reloading->integer && sv_reloading->integer != RELOAD_NEXTMAP ) { // game is in 'reload' mode, don't allow starting new maps yet.
			return;
		}

		// Trap a savegame load
		if ( strstr( map, ".sav" ) ) {
			// open the savegame, read the mapname, and copy it to the map string
			char savemap[MAX_QPATH];
			char savedir[MAX_QPATH];
			byte *buffer;
			int size, csize;

			if ( com_gameInfo.usesProfiles && cl_profileStr[0] ) {
				Com_sprintf( savedir, sizeof( savedir ), "profiles/%s/save/", cl_profileStr );
			} else {
				Q_strncpyz( savedir, "save/", sizeof( savedir ) );
			}

			if ( !( strstr( map, savedir ) == map ) ) {
				Com_sprintf( savemap, sizeof( savemap ), "%s%s", savedir, map );
			} else {
				strcpy( savemap, map );
			}

			size = FS_ReadFile( savemap, NULL );
			if ( size < 0 ) {
				Com_Printf( "Can't find savegame %s\n", savemap );
				return;
			}

			//buffer = Hunk_AllocateTempMemory(size);
			FS_ReadFile( savemap, (void **)&buffer );

			if ( Q_stricmp( savemap, va( "%scurrent.sav", savedir ) ) != 0 ) {
				// copy it to the current savegame file
				FS_WriteFile( va( "%scurrent.sav", savedir ), buffer, size );
				// make sure it is the correct size
				csize = FS_ReadFile( va( "%scurrent.sav", savedir ), NULL );
				if ( csize != size ) {
					Hunk_FreeTempMemory( buffer );
					FS_Delete( va( "%scurrent.sav", savedir ) );
// TTimo
#ifdef __linux__
					Com_Error( ERR_DROP, "Unable to save game.\n\nPlease check that you have at least 5mb free of disk space in your home directory." );
#else
					Com_Error( ERR_DROP, "Insufficient free disk space.\n\nPlease free at least 5mb of free space on game drive." );
#endif
					return;
				}
			}

			// set the cvar, so the game knows it needs to load the savegame once the clients have connected
			Cvar_Set( "savegame_loading", "1" );
			// set the filename
			Cvar_Set( "savegame_filename", savemap );

			// the mapname is at the very start of the savegame file
			Com_sprintf( savemap, sizeof( savemap ), ( char * )( buffer + sizeof( int ) ) );  // skip the version
			Q_strncpyz( smapname, savemap, sizeof( smapname ) );
			map = smapname;

			savegameTime = *( int * )( buffer + sizeof( int ) + MAX_QPATH );

			if ( savegameTime >= 0 ) {
				svs.time = savegameTime;
			}

			Hunk_FreeTempMemory( buffer );
		} else {
			Cvar_Set( "savegame_loading", "0" );  // make sure it's turned off
			// set the filename
			Cvar_Set( "savegame_filename", "" );
		}
	} else {
		Cvar_Set( "savegame_loading", "0" );  // make sure it's turned off
		// set the filename
		Cvar_Set( "savegame_filename", "" );
	}

	// make sure the level exists before trying to change, so that
	// a typo at the server console won't end the game
	Com_sprintf( expanded, sizeof( expanded ), "maps/%s.bsp", map );
	if ( FS_ReadFile( expanded, NULL ) == -1 ) {
		Com_Printf( "Can't find map %s\n", expanded );
		return;
	}

	Cvar_Set( "gamestate", va( "%i", GS_INITIALIZE ) );       // NERVE - SMF - reset gamestate on map/devmap

	Cvar_Set( "g_currentRound", "0" );            // NERVE - SMF - reset the current round
	Cvar_Set( "g_nextTimeLimit", "0" );           // NERVE - SMF - reset the next time limit

	// START	Mad Doctor I changes, 8/14/2002.  Need a way to force load a single player map as single player
	if ( !Q_stricmp( Cmd_Argv( 0 ), "spdevmap" ) || !Q_stricmp( Cmd_Argv( 0 ), "spmap" ) ) {
		// This is explicitly asking for a single player load of this map
		Cvar_Set( "g_gametype", va( "%i", com_gameInfo.defaultSPGameType ) );
		// force latched values to get set
		Cvar_Get( "g_gametype", va( "%i", com_gameInfo.defaultSPGameType ), CVAR_SERVERINFO | CVAR_USERINFO | CVAR_LATCH );
		// enable bot support for AI
		Cvar_Set( "bot_enable", "1" );
	}

	// Rafael gameskill
//	Cvar_Get ("g_gameskill", "3", CVAR_SERVERINFO | CVAR_LATCH);
	// done

	cmd = Cmd_Argv( 0 );

	if ( !Q_stricmp( cmd, "devmap" ) ) {
		cheat = qtrue;
		killBots = qtrue;
	} else
	if ( !Q_stricmp( Cmd_Argv( 0 ), "spdevmap" ) ) {
		cheat = qtrue;
		killBots = qtrue;
	} else
	{
		cheat = qfalse;
		killBots = qfalse;
	}

	// save the map name here cause on a map restart we reload the q3config.cfg
	// and thus nuke the arguments of the map command
	Q_strncpyz( mapname, map, sizeof( mapname ) );

	// start up the map
	SV_SpawnServer( mapname, killBots );

	// set the cheat value
	// if the level was started with "map <levelname>", then
	// cheats will not be allowed.  If started with "devmap <levelname>"
	// then cheats will be allowed
	if ( cheat ) {
		Cvar_Set( "sv_cheats", "1" );
	} else {
		Cvar_Set( "sv_cheats", "0" );
	}
}

static void SV_Putspec_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}

	if ( cl->state == CS_ACTIVE || cl->state == CS_PRIMED ) {
		Cmd_TokenizeString( "team s" );
		VM_Call( gvm, GAME_CLIENT_COMMAND, cl - svs.clients );
	}
}

static void SV_ClearVelocity_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	VectorClear( ps->velocity );
}

static void SV_GetVelocity_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	Cvar_Set( "returnvalue", va( "%f %f %f", ps->velocity[0], ps->velocity[1], ps->velocity[2] ) );
}

static void SV_SetVelocity_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	vec_t vel;
	char *ep;
	int i;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	for ( i = 0 ; i < 3 ; i++ ) {
		char *argv = Cmd_Argv( i + 2 );

		vel = strtod( argv, &ep );
		if ( ep == argv || *ep ) {
			Com_DPrintf( "unable to convert %s\n", ep );
			continue;
		}
		ps->velocity[i] = vel;
	}
}

static void SV_GetViewAngles_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	Cvar_Set( "returnvalue", va( "%f %f %f", ps->viewangles[0], ps->viewangles[1], ps->viewangles[2] ) );
}

static void SV_SetViewAngles_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	vec_t angle;
	char *ep;
	int i;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );

	for ( i = 0 ; i < 3 ; i++ ) {
		char *argv = Cmd_Argv( i + 2 );

		angle = strtod( argv, &ep );
		if ( ep == argv || *ep ) {
			Com_DPrintf( "unable to convert %s\n", ep );
			continue;
		}
		ps->viewangles[i] = angle;
		ps->delta_angles[i] = ANGLE2SHORT( ps->viewangles[i] ) - cl->lastUsercmd.angles[i];
	}
}

static void SV_GetPMFlagsAndTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	Cvar_Set( "returnvalue", va( "%d %d", ps->pm_flags, ps->pm_time ) );
}

static void SV_SetPMFlagsAndTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	ps->pm_flags = atoi( Cmd_Argv( 2 ) );
	ps->pm_time = atoi( Cmd_Argv( 3 ) );
}

static void SV_RemoveVoteFlag_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	ps->eFlags &= ~EF_VOTED;
}

static void SV_RemoveVoteFlags_f( void ) {
	int i;
	for ( i = 0; i < sv_maxclients->integer; i++ ) {
		if ( svs.clients[i].state >= CS_CONNECTED ) {
			playerState_t *ps = SV_GameClientNum( i );
			ps->eFlags &= ~EF_VOTED;
		}
	}
}

static void SV_ClearStatKey_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int statKey;

	if ( !cl ) {
		return;
	}

	statKey = atoi( Cmd_Argv( 2 ) );
	ps = SV_GameClientNum( cl - svs.clients );
	ps->stats[STAT_KEYS] &= ~( 1 << statKey );
}

static void SV_SetStatKey_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int statKey;

	if ( !cl ) {
		return;
	}

	statKey = atoi( Cmd_Argv( 2 ) );
	ps = SV_GameClientNum( cl - svs.clients );
	ps->stats[STAT_KEYS] |= 1 << statKey;
}

static void SV_GetClientName_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}

	Cvar_Set( "returnvalue", cl->name );
}

static void SV_SetClientName_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}

	Q_strncpyz( cl->name, Cmd_Argv( 2 ), sizeof( cl->name ) );
}

static void SV_WeaponCheck_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int weapon;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );

	weapon = atoi( Cmd_Argv( 2 ) );
	if ( COM_BitCheck( ps->weapons, weapon ) ) {
		Cvar_Set( "returnvalue", "true" );
	} else {
		Cvar_Set( "returnvalue", "false" );
	}
}

static void SV_WeaponSet_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int weapon;
	char *ep;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );	
	weapon = strtol( Cmd_Argv( 2 ), &ep, 10 );
	if ( *ep || ep == Cmd_Argv( 2 ) ) {
		Com_DPrintf( "unable to convert %s\n", ep );
		return;
	}
	COM_BitSet( ps->weapons, weapon );
}

static void SV_WeaponRemove_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int weapon;
	char *ep;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );		
	weapon = strtol( Cmd_Argv( 2 ), &ep, 10 );
	if ( *ep || ep == Cmd_Argv( 2 ) ) {
		Com_DPrintf( "unable to convert %s\n", ep );
		return;
	}
	COM_BitClear( ps->weapons, weapon );
}

static void SV_WeaponChange_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	int weapon;
	char *ep;

	if ( !cl ) {
		return;
	}

	weapon = strtol( Cmd_Argv( 2 ), &ep, 10 );
	if ( *ep || ep == Cmd_Argv( 2 ) ) {
		Com_DPrintf( "unable to convert %s\n", ep );
		return;
	}

	if ( weapon >= 0 && weapon < MAX_WEAPONS ) {
		playerState_t *ps = SV_GameClientNum( cl - svs.clients );
		
		ps->weapon = weapon;
	}
}

static void SV_WeaponLeave_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	weapon_t weapons[MAX_WEAPONS] = { WP_NONE };
	int indexWeapons = 0;
	int i;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );

	for ( i = 0 ; i + 2 < Cmd_Argc() && i < MAX_WEAPONS ; i++ ) {
		char *argv = Cmd_Argv( i + 2 );
		char *ep;
		int weapon = strtol( argv, &ep, 10 );

		if ( ep == argv || *ep ) {
			Com_DPrintf( "unable to convert %s\n", ep );
			continue;
		}

		if ( COM_BitCheck( ps->weapons, weapon ) ) {
			weapons[indexWeapons] = weapon;
			indexWeapons++;
		}
	}

	ps->weapons[0] = 0;
	ps->weapons[1] = 0;

	for ( i = 0 ; i < indexWeapons ; i++ ) {
		COM_BitSet( ps->weapons, weapons[i] );
	}

	if ( !COM_BitCheck( ps->weapons, ps->weapon ) ) {
		ps->weapon = weapons[0];
	}
}

static void SV_GetWeaponState_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	Cvar_Set( "returnvalue", va( "%d", ps->weaponstate ) );
}

static void SV_SetWeaponState_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int weaponstate;

	if ( !cl ) {
		return;
	}

	weaponstate = atoi( Cmd_Argv( 2 ) );

	ps = SV_GameClientNum( cl - svs.clients );
		
	ps->weaponstate = weaponstate;
}

static void SV_GetClassWeaponTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;

	if ( !cl ) {
		return;
	}

	ps = SV_GameClientNum( cl - svs.clients );
	Cvar_Set( "returnvalue", va( "%d", ps->classWeaponTime ) );
}

static void SV_SetClassWeaponTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	playerState_t *ps;
	int classWeaponTime;

	if ( !cl ) {
		return;
	}

	classWeaponTime = atoi( Cmd_Argv( 2 ) );

	ps = SV_GameClientNum( cl - svs.clients );
	ps->classWeaponTime = classWeaponTime;
}

static void SV_GetLastActivityTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}

	if ( Cmd_Argc() >= 3 ) {
		char *type = Cmd_Argv( 2 );
		int time = 0;

		if ( Q_stricmp( type, "buttons" ) == 0 || Q_stricmp( type, "button" ) == 0 ) {
			int flags;
			char *ep;
			int i;

			flags = strtol( Cmd_Argv( 3 ), &ep, 0 );
			if ( *ep || ep == Cmd_Argv( 3 ) ) {
				return;
			}

			for ( i = 0 ; i < 8 ; i++ ) {
				if ( flags & 1 << i && cl->lastUsercmdTimes.buttons[i] > time ) {
					time = cl->lastUsercmdTimes.buttons[i];
				}
			}
		} else if ( Q_stricmp( type, "wbuttons" ) == 0 || Q_stricmp( type, "wbutton" ) == 0 ) {
			int flags;
			char *ep;
			int i;

			flags = strtol( Cmd_Argv( 3 ), &ep, 0 );
			if ( *ep || ep == Cmd_Argv( 3 ) ) {
				return;
			}

			for ( i = 0 ; i < 8 ; i++ ) {
				if ( flags & 1 << i && cl->lastUsercmdTimes.wbuttons[i] > time ) {
					time = cl->lastUsercmdTimes.wbuttons[i];
				}
			}
		} else if ( Q_stricmp( type, "forwardmove" ) == 0 ) {
			time = cl->lastUsercmdTimes.forwardmove;
		} else if ( Q_stricmp( type, "rightmove" ) == 0 ) {
			time = cl->lastUsercmdTimes.rightmove;
		} else if ( Q_stricmp( type, "upmove" ) == 0 ) {
			time = cl->lastUsercmdTimes.upmove;
		} else {
			return;
		}

		Cvar_Set( "returnvalue", va( "%d", time ) );
	} else {
		Cvar_Set( "returnvalue", va( "%d", cl->lastActivityTime ) );
	}
}

static void SV_ListMaps_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}
	SV_ListMaps( cl );
}

static void SV_MapList_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		return;
	}
	SV_MapList( cl );
}

static void SV_FindMap_f( void ) {
	if ( strcmp( Cmd_Argv( 1 ), "r" ) == 0 ) {
		SV_FindMap( NULL, 2 );
	} else {
		SV_FindMap( SV_GetPlayerByNum(), 2 );
	}
}

static void SV_SetFindMapTime_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	int time;
	char *ep;

	if ( !cl ) {
		return;
	}

	time = strtol( Cmd_Argv( 2 ), &ep, 10 );
	if ( *ep ) {
		return;
	} else if ( ep == Cmd_Argv( 2 ) ) {
		time = -99999;
	}
	SV_SetFindMapTime( cl - svs.clients, time );
}

static void SV_CheckClientPak_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl || Cmd_Argc() < 3 ) {
		return;
	}

	if ( FS_ClientHasPak( cl, Cmd_Argv( 2 ) ) ) {
		Cvar_Set( "returnvalue", "true" );
	} else {
		Cvar_Set( "returnvalue", "false" );
	}
}

static void SV_SendServerCommand_f( void ) {
	client_t *cl = SV_GetPlayerByNum();

	if ( !cl ) {
		if ( atoi( Cmd_Argv( 1 ) ) == -1 ) {
			cl = NULL;
		} else {
			return;
		}
	}

	SV_SendServerCommand( cl, "%s", Cmd_ArgsFrom( 2 ) );
}

static void SV_SetLevelTime_f( void ) {
	char *argv1;
	int time;
	char *endptr;
	const char *strUsage = "Usage: setleveltime <time>\n";

#if 0
	if ( !com_developer || !com_developer->integer ) {
		return;
	}
#endif
	if ( Cmd_Argc() != 2 ) {
		Com_Printf( strUsage );
		return;
	}
	argv1 = Cmd_Argv( 1 );
	time = strtol( argv1, &endptr, 0 );
	if ( endptr == argv1 || *endptr ) {
		Com_Printf( strUsage );
		return;
	}
	svs.time = time;
	Com_Printf( "Set svs.time to 0x%08X.\n", time );
}

static void SV_ShowServerTime_f( void ) {
	char *argv1 = Cmd_Argv( 1 );

	if ( Q_stricmp( argv1, "lastPlayerLeftTime" ) == 0 ) {
		Com_Printf( "svs.lastPlayerLeftTime:0x%08X\n", svs.lastPlayerLeftTime );
	} else if ( Q_stricmp( argv1, "tempRestartTime" ) == 0 ) {
		Com_Printf( "svs.tempRestartTime:0x%08X\n", svs.tempRestartTime );
	} else {
		Com_Printf( "svs.time:0x%08X\n", svs.time );
	}
	return;
}

static void SV_GetClState_f( void ) {
	client_t *cl = SV_GetPlayerByNum();
	if ( !cl ) {
		return;
	}

	switch ( cl->state ) {
		case CS_FREE:
			Com_Printf( "CS_FREE\n" );
			break;
		case CS_ZOMBIE:
			Com_Printf( "CS_ZOMBIE\n" );
			break;
		case CS_CONNECTED:
			Com_Printf( "CS_CONNECTED\n" );
			break;
		case CS_PRIMED:
			Com_Printf( "CS_PRIMED\n" );
			break;
		case CS_ACTIVE:
			Com_Printf( "CS_ACTIVE\n" );
			break;
	}
}

void SV_Rcon_f( void ) {
	char message[1024];
	netadr_t to;

	if ( !*rcon_client_password->string ) {
		Com_Printf( "You must set 'rconPassword' before\n"
					"issuing an rcon command.\n" );
		return;
	}

	message[0] = -1;
	message[1] = -1;
	message[2] = -1;
	message[3] = -1;
	message[4] = 0;

	strcat( message, "rcon " );

	strcat( message, rcon_client_password->string );
	strcat( message, " " );

	// ATVI Wolfenstein Misc #284
	strcat( message, Cmd_Cmd() + 5 );

	if ( !strlen( rconAddress->string ) ) {
		Com_Printf( "You must either be connected,\n"
					"or set the 'rconAddress' cvar\n"
					"to issue rcon commands\n" );

		return;
	}
	NET_StringToAdr( rconAddress->string, &to );
	if ( to.port == 0 ) {
		to.port = BigShort( PORT_SERVER );
	}

	NET_SendPacket( NS_SERVER, strlen( message ) + 1, message, to );
}

/*
================
SV_CheckTransitionGameState

NERVE - SMF
================
*/
static qboolean SV_CheckTransitionGameState( gamestate_t new_gs, gamestate_t old_gs ) {
	if ( old_gs == new_gs && new_gs != GS_PLAYING ) {
		return qfalse;
	}

//	if ( old_gs == GS_WARMUP && new_gs != GS_WARMUP_COUNTDOWN )
//		return qfalse;

//	if ( old_gs == GS_WARMUP_COUNTDOWN && new_gs != GS_PLAYING )
//		return qfalse;

	if ( old_gs == GS_WAITING_FOR_PLAYERS && new_gs != GS_WARMUP ) {
		return qfalse;
	}

	if ( old_gs == GS_INTERMISSION && new_gs != GS_WARMUP ) {
		return qfalse;
	}

	if ( old_gs == GS_RESET && ( new_gs != GS_WAITING_FOR_PLAYERS && new_gs != GS_WARMUP ) ) {
		return qfalse;
	}

	return qtrue;
}

/*
================
SV_TransitionGameState

NERVE - SMF
================
*/
static qboolean SV_TransitionGameState( gamestate_t new_gs, gamestate_t old_gs, int delay ) {
	if ( !SV_GameIsSinglePlayer() && !SV_GameIsCoop() ) {
		// we always do a warmup before starting match
		if ( old_gs == GS_INTERMISSION && new_gs == GS_PLAYING ) {
			new_gs = GS_WARMUP;
		}
	}

	// check if its a valid state transition
	if ( !SV_CheckTransitionGameState( new_gs, old_gs ) ) {
		return qfalse;
	}

	if ( new_gs == GS_RESET ) {
		new_gs = GS_WARMUP;
	}

	Cvar_Set( "gamestate", va( "%i", new_gs ) );

	return qtrue;
}

void MSG_PrioritiseEntitystateFields( void );
void MSG_PrioritisePlayerStateFields( void );

static void SV_FieldInfo_f( void ) {
	MSG_PrioritiseEntitystateFields();
	MSG_PrioritisePlayerStateFields();
}

/*
================
SV_MapRestart_f

Completely restarts a level, but doesn't send a new gamestate to the clients.
This allows fair starts with variable load times.
================
*/
static void SV_MapRestart_f( void ) {
	int i;
	client_t    *client;
	char        *denied;
	qboolean isBot;
	int delay = 0;
	gamestate_t new_gs, old_gs;     // NERVE - SMF

	// make sure we aren't restarting twice in the same frame
	if ( com_frameTime == sv.serverId ) {
		return;
	}

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	// ydnar: allow multiple delayed server restarts [atvi bug 3813]
	//%	if ( sv.restartTime ) {
	//%		return;
	//%	}

	if ( Cmd_Argc() > 1 ) {
		delay = atoi( Cmd_Argv( 1 ) );
	}

	if ( delay ) {
		sv.restartTime = svs.time + delay * 1000;
		SV_SetConfigstring( CS_WARMUP, va( "%i", sv.restartTime ) );
		return;
	}

	// NERVE - SMF - read in gamestate or just default to GS_PLAYING
	old_gs = atoi( Cvar_VariableString( "gamestate" ) );

	if ( SV_GameIsSinglePlayer() || SV_GameIsCoop() ) {
		new_gs = GS_PLAYING;
	} else {
		if ( Cmd_Argc() > 2 ) {
			new_gs = atoi( Cmd_Argv( 2 ) );
		} else {
			new_gs = GS_PLAYING;
		}
	}

	if ( !SV_TransitionGameState( new_gs, old_gs, delay ) ) {
		return;
	}

	// check for changes in variables that can't just be restarted
	// check for maxclients change
	if ( sv_maxclients->modified ) {
		char mapname[MAX_QPATH];

		Com_Printf( "sv_maxclients variable change -- restarting.\n" );
		// restart the map the slow way
		Q_strncpyz( mapname, Cvar_VariableString( "mapname" ), sizeof( mapname ) );

		SV_SpawnServer( mapname, qfalse );
		return;
	}

	// Check for loading a saved game
	if ( Cvar_VariableIntegerValue( "savegame_loading" ) ) {
		// open the current savegame, and find out what the time is, everything else we can ignore
		char savemap[MAX_QPATH];
		byte *buffer;
		int size, savegameTime;
		char *cl_profileStr = Cvar_VariableString( "cl_profile" );

		if ( com_gameInfo.usesProfiles ) {
			Com_sprintf( savemap, sizeof( savemap ), "profiles/%s/save/current.sav", cl_profileStr );
		} else {
			Q_strncpyz( savemap, "save/current.sav", sizeof( savemap ) );
		}

		size = FS_ReadFile( savemap, NULL );
		if ( size < 0 ) {
			Com_Printf( "Can't find savegame %s\n", savemap );
			return;
		}

		//buffer = Hunk_AllocateTempMemory(size);
		FS_ReadFile( savemap, (void **)&buffer );

		// the mapname is at the very start of the savegame file
		savegameTime = *( int * )( buffer + sizeof( int ) + MAX_QPATH );

		if ( savegameTime >= 0 ) {
			svs.time = savegameTime;
		}

		Hunk_FreeTempMemory( buffer );
	}
	// done.

	// toggle the server bit so clients can detect that a
	// map_restart has happened
	svs.snapFlagServerBit ^= SNAPFLAG_SERVERCOUNT;

	// generate a new serverid
	// TTimo - don't update restartedserverId there, otherwise we won't deal correctly with multiple map_restart
	sv.serverId = com_frameTime;
	Cvar_Set( "sv_serverid", va( "%i", sv.serverId ) );

	// reset all the vm data in place without changing memory allocation
	// note that we do NOT set sv.state = SS_LOADING, so configstrings that
	// had been changed from their default values will generate broadcast updates
	sv.state = SS_LOADING;
	sv.restarting = qtrue;

	Cvar_Set( "sv_serverRestarting", "1" );

	SV_RestartGameProgs();

	// run a few frames to allow everything to settle
	for ( i = 0; i < GAME_INIT_FRAMES; i++ ) {
		VM_Call( gvm, GAME_RUN_FRAME, svs.time );
		svs.time += FRAMETIME;
	}

	// create a baseline for more efficient communications
	// Gordon: meh, this wont work here as the client doesn't know it has happened
//	SV_CreateBaseline ();

	sv.state = SS_GAME;
	sv.restarting = qfalse;

	// connect and begin all the clients
	for ( i = 0 ; i < sv_maxclients->integer ; i++ ) {
		client = &svs.clients[i];

		// send the new gamestate to all connected clients
		if ( client->state < CS_CONNECTED ) {
			continue;
		}

		if ( client->netchan.remoteAddress.type == NA_BOT ) {
			if ( SV_GameIsSinglePlayer() || SV_GameIsCoop() ) {
				continue;   // dont carry across bots in single player
			}
			isBot = qtrue;
		} else {
			isBot = qfalse;
		}

		// add the map_restart command
		SV_AddServerCommand( client, "map_restart\n" );

		// connect the client again, without the firstTime flag
		denied = VM_ExplicitArgPtr( gvm, VM_Call( gvm, GAME_CLIENT_CONNECT, i, qfalse, isBot ) );
		if ( denied ) {
			// this generally shouldn't happen, because the client
			// was connected before the level change
			SV_DropClient( client, denied );
			if ( ( !SV_GameIsSinglePlayer() ) || ( !isBot ) ) {
				Com_Printf( "SV_MapRestart_f(%d): dropped client %i - denied!\n", delay, i ); // bk010125
			}
			continue;
		}

		client->state = CS_ACTIVE;

		SV_ClientEnterWorld( client, &client->lastUsercmd );
	}

	// run another frame to allow things to look at all the players
	VM_Call( gvm, GAME_RUN_FRAME, svs.time );
	svs.time += FRAMETIME;

	Cvar_Set( "sv_serverRestarting", "0" );
}

/*
=================
SV_LoadGame_f
=================
*/
void    SV_LoadGame_f( void ) {
	char filename[MAX_QPATH], mapname[MAX_QPATH], savedir[MAX_QPATH];
	byte *buffer;
	int size;
	char *cl_profileStr = Cvar_VariableString( "cl_profile" );

	// dont allow command if another loadgame is pending
	if ( Cvar_VariableIntegerValue( "savegame_loading" ) ) {
		return;
	}
	if ( sv_reloading->integer ) {
		// (SA) disabling
//	if(sv_reloading->integer && sv_reloading->integer != RELOAD_FAILED )	// game is in 'reload' mode, don't allow starting new maps yet.
		return;
	}

	Q_strncpyz( filename, Cmd_Argv( 1 ), sizeof( filename ) );
	if ( !filename[0] ) {
		Com_Printf( "You must specify a savegame to load\n" );
		return;
	}

	if ( com_gameInfo.usesProfiles && cl_profileStr[0] ) {
		Com_sprintf( savedir, sizeof( savedir ), "profiles/%s/save/", cl_profileStr );
	} else {
		Q_strncpyz( savedir, "save/", sizeof( savedir ) );
	}

	/*if ( Q_strncmp( filename, "save/", 5 ) && Q_strncmp( filename, "save\\", 5 ) ) {
		Q_strncpyz( filename, va("save/%s", filename), sizeof( filename ) );
	}*/

	// go through a va to avoid vsnprintf call with same source and target
	Q_strncpyz( filename, va( "%s%s", savedir, filename ), sizeof( filename ) );

	// enforce .sav extension
	if ( !strstr( filename, "." ) || Q_strncmp( strstr( filename, "." ) + 1, "sav", 3 ) ) {
		Q_strcat( filename, sizeof( filename ), ".sav" );
	}
	// use '/' instead of '\\' for directories
	while ( strstr( filename, "\\" ) ) {
		*(char *)strstr( filename, "\\" ) = '/';
	}

	size = FS_ReadFile( filename, NULL );
	if ( size < 0 ) {
		Com_Printf( "Can't find savegame %s\n", filename );
		return;
	}

	//buffer = Hunk_AllocateTempMemory(size);
	FS_ReadFile( filename, (void **)&buffer );

	// read the mapname, if it is the same as the current map, then do a fast load
	Com_sprintf( mapname, sizeof( mapname ), (const char*)( buffer + sizeof( int ) ) );

	if ( com_sv_running->integer && ( com_frameTime != sv.serverId ) ) {
		// check mapname
		if ( !Q_stricmp( mapname, sv_mapname->string ) ) {    // same

			if ( Q_stricmp( filename, va( "%scurrent.sav",savedir ) ) != 0 ) {
				// copy it to the current savegame file
				FS_WriteFile( va( "%scurrent.sav",savedir ), buffer, size );
			}

			Hunk_FreeTempMemory( buffer );

			Cvar_Set( "savegame_loading", "2" );  // 2 means it's a restart, so stop rendering until we are loaded
			// set the filename
			Cvar_Set( "savegame_filename", filename );
			// quick-restart the server
			SV_MapRestart_f();  // savegame will be loaded after restart

			return;
		}
	}

	Hunk_FreeTempMemory( buffer );

	// otherwise, do a slow load
	if ( Cvar_VariableIntegerValue( "sv_cheats" ) ) {
		Cbuf_ExecuteText( EXEC_APPEND, va( "spdevmap %s", filename ) );
	} else {    // no cheats
		Cbuf_ExecuteText( EXEC_APPEND, va( "spmap %s", filename ) );
	}
}

//===============================================================

/*
==================
SV_Kick_f

Kick a user off of the server  FIXME: move to game
// fretn: done
==================
*/
/*
static void SV_Kick_f( void ) {
	client_t	*cl;
	int			i;
	int			timeout = -1;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() < 2 || Cmd_Argc() > 3 ) {
		Com_Printf ("Usage: kick <player name> [timeout]\n");
		return;
	}

	if( Cmd_Argc() == 3 ) {
		timeout = atoi( Cmd_Argv( 2 ) );
	} else {
		timeout = 300;
	}

	cl = SV_GetPlayerByName();
	if ( !cl ) {
		if ( !Q_stricmp(Cmd_Argv(1), "all") ) {
			for( i = 0, cl = svs.clients; i < sv_maxclients->integer; i++, cl++ ) {
				if ( !cl->state ) {
					continue;
				}
				if( cl->netchan.remoteAddress.type == NA_LOOPBACK ) {
					continue;
				}
				SV_DropClient( cl, "player kicked" ); // JPW NERVE to match front menu message
				if( timeout != -1 ) {
					SV_TempBanNetAddress( cl->netchan.remoteAddress, timeout );
				}
				cl->lastPacketTime = svs.time;	// in case there is a funny zombie
			}
		} else if ( !Q_stricmp(Cmd_Argv(1), "allbots") ) {
			for ( i=0, cl=svs.clients ; i < sv_maxclients->integer ; i++,cl++ ) {
				if ( !cl->state ) {
					continue;
				}
				if( cl->netchan.remoteAddress.type != NA_BOT ) {
					continue;
				}
				SV_DropClient( cl, "was kicked" );
				if( timeout != -1 ) {
					SV_TempBanNetAddress( cl->netchan.remoteAddress, timeout );
				}
				cl->lastPacketTime = svs.time;	// in case there is a funny zombie
			}
		}
		return;
	}
	if( cl->netchan.remoteAddress.type == NA_LOOPBACK ) {
		SV_SendServerCommand(NULL, "print \"%s\"", "Cannot kick host player\n");
		return;
	}

	SV_DropClient( cl, "player kicked" ); // JPW NERVE to match front menu message
	if( timeout != -1 ) {
		SV_TempBanNetAddress( cl->netchan.remoteAddress, timeout );
	}
	cl->lastPacketTime = svs.time;	// in case there is a funny zombie
}
*/

#ifdef AUTHORIZE_SUPPORT
/*
==================
SV_Ban_f

Ban a user from being able to play on this server through the auth
server
==================
*/
static void SV_Ban_f( void ) {
	client_t    *cl;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() != 2 ) {
		Com_Printf( "Usage: banUser <player name>\n" );
		return;
	}

	cl = SV_GetPlayerByName();

	if ( !cl ) {
		return;
	}

	if ( cl->netchan.remoteAddress.type == NA_LOOPBACK ) {
		SV_SendServerCommand( NULL, "print \"%s\"", "Cannot kick host player\n" );
		return;
	}

	// look up the authorize server's IP
	if ( !svs.authorizeAddress.ip[0] && svs.authorizeAddress.type != NA_BAD ) {
		Com_Printf( "Resolving %s\n", AUTHORIZE_SERVER_NAME );
		if ( !NET_StringToAdr( AUTHORIZE_SERVER_NAME, &svs.authorizeAddress ) ) {
			Com_Printf( "Couldn't resolve address\n" );
			return;
		}
		svs.authorizeAddress.port = BigShort( PORT_AUTHORIZE );
		Com_Printf( "%s resolved to %i.%i.%i.%i:%i\n", AUTHORIZE_SERVER_NAME,
					svs.authorizeAddress.ip[0], svs.authorizeAddress.ip[1],
					svs.authorizeAddress.ip[2], svs.authorizeAddress.ip[3],
					BigShort( svs.authorizeAddress.port ) );
	}

	// otherwise send their ip to the authorize server
	if ( svs.authorizeAddress.type != NA_BAD ) {
		NET_OutOfBandPrint( NS_SERVER, svs.authorizeAddress,
							"banUser %i.%i.%i.%i", cl->netchan.remoteAddress.ip[0], cl->netchan.remoteAddress.ip[1],
							cl->netchan.remoteAddress.ip[2], cl->netchan.remoteAddress.ip[3] );
		Com_Printf( "%s was banned from coming back\n", cl->name );
	}
}

/*
==================
SV_BanNum_f

Ban a user from being able to play on this server through the auth
server
==================
*/
static void SV_BanNum_f( void ) {
	client_t    *cl;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() != 2 ) {
		Com_Printf( "Usage: banClient <client number>\n" );
		return;
	}

	cl = SV_GetPlayerByNum();
	if ( !cl ) {
		return;
	}
	if ( cl->netchan.remoteAddress.type == NA_LOOPBACK ) {
		SV_SendServerCommand( NULL, "print \"%s\"", "Cannot kick host player\n" );
		return;
	}

	// look up the authorize server's IP
	if ( !svs.authorizeAddress.ip[0] && svs.authorizeAddress.type != NA_BAD ) {
		Com_Printf( "Resolving %s\n", AUTHORIZE_SERVER_NAME );
		if ( !NET_StringToAdr( AUTHORIZE_SERVER_NAME, &svs.authorizeAddress ) ) {
			Com_Printf( "Couldn't resolve address\n" );
			return;
		}
		svs.authorizeAddress.port = BigShort( PORT_AUTHORIZE );
		Com_Printf( "%s resolved to %i.%i.%i.%i:%i\n", AUTHORIZE_SERVER_NAME,
					svs.authorizeAddress.ip[0], svs.authorizeAddress.ip[1],
					svs.authorizeAddress.ip[2], svs.authorizeAddress.ip[3],
					BigShort( svs.authorizeAddress.port ) );
	}

	// otherwise send their ip to the authorize server
	if ( svs.authorizeAddress.type != NA_BAD ) {
		NET_OutOfBandPrint( NS_SERVER, svs.authorizeAddress,
							"banUser %i.%i.%i.%i", cl->netchan.remoteAddress.ip[0], cl->netchan.remoteAddress.ip[1],
							cl->netchan.remoteAddress.ip[2], cl->netchan.remoteAddress.ip[3] );
		Com_Printf( "%s was banned from coming back\n", cl->name );
	}
}
#endif // AUTHORIZE_SUPPORT

/*
==================
==================
*/
void SV_TempBanNetAddress( netadr_t address, int length ) {
	int i;
	int oldesttime = 0;
	int oldest = -1;

	for ( i = 0; i < MAX_TEMPBAN_ADDRESSES; i++ ) {
		if ( !svs.tempBanAddresses[ i ].endtime || svs.tempBanAddresses[ i ].endtime < svs.time ) {
			// found a free slot
			svs.tempBanAddresses[ i ].adr       = address;
			svs.tempBanAddresses[ i ].endtime   = svs.time + ( length * 1000 );

			return;
		} else {
			if ( oldest == -1 || oldesttime > svs.tempBanAddresses[ i ].endtime ) {
				oldesttime  = svs.tempBanAddresses[ i ].endtime;
				oldest      = i;
			}
		}
	}

	svs.tempBanAddresses[ oldest ].adr      = address;
	svs.tempBanAddresses[ oldest ].endtime  = svs.time + length;
}

qboolean SV_TempBanIsBanned( netadr_t address ) {
	int i;

	for ( i = 0; i < MAX_TEMPBAN_ADDRESSES; i++ ) {
		if ( svs.tempBanAddresses[ i ].endtime && svs.tempBanAddresses[ i ].endtime > svs.time ) {
			if ( NET_CompareAdr( address, svs.tempBanAddresses[ i ].adr ) ) {
				return qtrue;
			}
		}
	}

	return qfalse;
}

/*
==================
SV_KickNum_f

Kick a user off of the server  FIXME: move to game
*DONE*
==================
*/
/*
static void SV_KickNum_f( void ) {
	client_t	*cl;
	int timeout = -1;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() < 2 || Cmd_Argc() > 3 ) {
		Com_Printf ("Usage: kicknum <client number> [timeout]\n");
		return;
	}

	if( Cmd_Argc() == 3 ) {
		timeout = atoi( Cmd_Argv( 2 ) );
	} else {
		timeout = 300;
	}

	cl = SV_GetPlayerByNum();
	if ( !cl ) {
		return;
	}
	if( cl->netchan.remoteAddress.type == NA_LOOPBACK ) {
		SV_SendServerCommand(NULL, "print \"%s\"", "Cannot kick host player\n");
		return;
	}

	SV_DropClient( cl, "player kicked" );
	if( timeout != -1 ) {
		SV_TempBanNetAddress( cl->netchan.remoteAddress, timeout );
	}
	cl->lastPacketTime = svs.time;	// in case there is a funny zombie
}
*/
/*
================
SV_Status_f
================
*/
static void SV_Status_f( void ) {
	int i, j, l;
	client_t    *cl;
	playerState_t   *ps;
	const char      *s;
	int ping;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	Com_Printf( "map: %s\n", sv_mapname->string );

	Com_Printf( "num score ping name            lastmsg address               qport rate\n" );
	Com_Printf( "--- ----- ---- --------------- ------- --------------------- ----- -----\n" );
	for ( i = 0,cl = svs.clients ; i < sv_maxclients->integer ; i++,cl++ )
	{
		if ( !cl->state ) {
			continue;
		}
		Com_Printf( "%3i ", i );
		ps = SV_GameClientNum( i );
		Com_Printf( "%5i ", ps->persistant[PERS_SCORE] );

		if ( cl->state == CS_CONNECTED ) {
			Com_Printf( "CNCT " );
		} else if ( cl->state == CS_ZOMBIE ) {
			Com_Printf( "ZMBI " );
		} else
		{
			ping = cl->ping < 9999 ? cl->ping : 9999;
			Com_Printf( "%4i ", ping );
		}

		Com_Printf( "%s", cl->name );
		l = 16 - strlen( cl->name );
		for ( j = 0 ; j < l ; j++ )
			Com_Printf( " " );

		Com_Printf( "%7i ", svs.time - cl->lastPacketTime );

		s = NET_AdrToString( cl->netchan.remoteAddress );
		Com_Printf( "%s", s );
		l = 22 - strlen( s );
		for ( j = 0 ; j < l ; j++ )
			Com_Printf( " " );

		Com_Printf( "%5i", cl->netchan.qport );

		Com_Printf( " %5i", cl->rate );

		Com_Printf( "\n" );
	}
	Com_Printf( "\n" );
}

/*
==================
SV_ConSay_f
==================
*/
static void SV_ConSay_f( void ) {
	char    *p;
	char text[1024];

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() < 2 ) {
		return;
	}

	strcpy( text, "console: " );
	p = Cmd_Args();

	if ( *p == '"' ) {
		p++;
		p[strlen( p ) - 1] = 0;
	}

	strcat( text, p );

	SV_SendServerCommand( NULL, "chat \"%s\"", text );
}


/*
==================
SV_Heartbeat_f

Also called by SV_DropClient, SV_DirectConnect, and SV_SpawnServer
==================
*/
void SV_Heartbeat_f( void ) {
	svs.nextHeartbeatTime = -9999999;
}


/*
===========
SV_Serverinfo_f

Examine the serverinfo string
===========
*/
static void SV_Serverinfo_f( void ) {
	Com_Printf( "Server info settings:\n" );
	Info_Print( Cvar_InfoString( CVAR_SERVERINFO | CVAR_SERVERINFO_NOUPDATE ) );
}


/*
===========
SV_Systeminfo_f

Examine or change the serverinfo string
===========
*/
static void SV_Systeminfo_f( void ) {
	char buf[BIG_INFO_STRING];

	SV_GetConfigstring( CS_SYSTEMINFO, buf, sizeof( buf ) );

	if ( Cmd_Argc() == 2 ) {
		if ( Q_stricmpn( Cmd_Argv( 1 ), "len", 3 ) == 0 ) {
			Com_Printf( "total length: %d\n", strlen( buf ) );
			return;
		} else {
			char *info;

			info = Info_ValueForKey( buf, Cmd_Argv( 1 ) );
			if ( *info ) {
				char *s = info;

				while ( *s ) {
					char text[1024];
					int i;

					for ( i = 0; *s && i < sizeof ( text ) - 1; i++, s++ ) {
						text[i] = *s;
					}
					text[i] = 0;

					Com_Printf( "%s", text );
				}
				Com_Printf( "\n" );
			}
			return;
		}
	}

	Com_Printf( "System info settings:\n" );
	Info_Print( buf );
}


/*
===========
SV_DumpUser_f

Examine all a users info strings FIXME: move to game
===========
*/
static void SV_DumpUser_f( void ) {
	client_t    *cl;

	// make sure server is running
	if ( !com_sv_running->integer ) {
		Com_Printf( "Server is not running.\n" );
		return;
	}

	if ( Cmd_Argc() != 2 ) {
		Com_Printf( "Usage: info <userid>\n" );
		return;
	}

	cl = SV_GetPlayerByName();
	if ( !cl ) {
		return;
	}

	Com_Printf( "userinfo\n" );
	Com_Printf( "--------\n" );
	Info_Print( cl->userinfo );
}


/*
=================
SV_KillServer
=================
*/
static void SV_KillServer_f( void ) {
	SV_Shutdown( "killserver" );
}

/*
=================
SV_GameCompleteStatus_f

NERVE - SMF
=================
*/
void SV_GameCompleteStatus_f( void ) {
	SV_MasterGameCompleteStatus();
}

//===========================================================

/*
==================
SV_AddOperatorCommands
==================
*/
void SV_AddOperatorCommands( void ) {
	static qboolean initialized;

	if ( initialized ) {
		return;
	}
	initialized = qtrue;

	Cmd_AddCommand( "heartbeat", SV_Heartbeat_f );
// fretn - moved to qagame
	/*Cmd_AddCommand ("kick", SV_Kick_f);
	Cmd_AddCommand ("clientkick", SV_KickNum_f);*/
#ifdef AUTHORIZE_SUPPORT
	// Arnout: banning requires auth server
	Cmd_AddCommand( "banUser", SV_Ban_f );
	Cmd_AddCommand( "banClient", SV_BanNum_f );
#endif // AUTHORIZE_SUPPORT
	Cmd_AddCommand( "status", SV_Status_f );
	Cmd_AddCommand( "serverinfo", SV_Serverinfo_f );
	Cmd_AddCommand( "systeminfo", SV_Systeminfo_f );
	Cmd_AddCommand( "dumpuser", SV_DumpUser_f );
	Cmd_AddCommand( "map_restart", SV_MapRestart_f );
	//
	Cmd_AddCommand( "putspec", SV_Putspec_f );
	Cmd_AddCommand( "clearvelocity", SV_ClearVelocity_f );
	Cmd_AddCommand( "removevoteflag", SV_RemoveVoteFlag_f );
	Cmd_AddCommand( "removevoteflags", SV_RemoveVoteFlags_f );
	Cmd_AddCommand( "clearstatkey", SV_ClearStatKey_f );
	Cmd_AddCommand( "setstatkey", SV_SetStatKey_f );
	Cmd_AddCommand( "getvelocity", SV_GetVelocity_f );
	Cmd_AddCommand( "setvelocity", SV_SetVelocity_f );
	Cmd_AddCommand( "getviewangles", SV_GetViewAngles_f );
	Cmd_AddCommand( "setviewangles", SV_SetViewAngles_f );
	Cmd_AddCommand( "getpmflagsandtime", SV_GetPMFlagsAndTime_f );
	Cmd_AddCommand( "setpmflagsandtime", SV_SetPMFlagsAndTime_f );
	Cmd_AddCommand( "getclientname", SV_GetClientName_f );
	Cmd_AddCommand( "setclientname", SV_SetClientName_f );
	Cmd_AddCommand( "weaponcheck", SV_WeaponCheck_f );
	Cmd_AddCommand( "weaponset", SV_WeaponSet_f );
	Cmd_AddCommand( "weaponremove", SV_WeaponRemove_f );
	Cmd_AddCommand( "weaponchange", SV_WeaponChange_f );
	Cmd_AddCommand( "weaponleave", SV_WeaponLeave_f );
	Cmd_AddCommand( "getweaponstate", SV_GetWeaponState_f );
	Cmd_AddCommand( "setweaponstate", SV_SetWeaponState_f );
	Cmd_AddCommand( "getclassweapontime", SV_GetClassWeaponTime_f );
	Cmd_AddCommand( "setclassweapontime", SV_SetClassWeaponTime_f );
	Cmd_AddCommand( "getlastactivitytime", SV_GetLastActivityTime_f );
	Cmd_AddCommand( "listmaps", SV_ListMaps_f );
	Cmd_AddCommand( "maplist", SV_MapList_f );
	Cmd_AddCommand( "findmap", SV_FindMap_f );
	Cmd_AddCommand( "setfindmaptime", SV_SetFindMapTime_f );
	Cmd_AddCommand( "checkclientpak", SV_CheckClientPak_f );
	Cmd_AddCommand( "sendservercommand", SV_SendServerCommand_f );
	Cmd_AddCommand( "setleveltime", SV_SetLevelTime_f );
	Cmd_AddCommand( "svstime", SV_ShowServerTime_f );
	Cmd_AddCommand( "getclstate", SV_GetClState_f );
	Cmd_AddCommand( "rcon", SV_Rcon_f );
	//
	Cmd_AddCommand( "fieldinfo", SV_FieldInfo_f );
	Cmd_AddCommand( "sectorlist", SV_SectorList_f );
	Cmd_AddCommand( "map", SV_Map_f );
	Cmd_AddCommand( "gameCompleteStatus", SV_GameCompleteStatus_f );      // NERVE - SMF
#ifndef PRE_RELEASE_DEMO_NODEVMAP
	Cmd_AddCommand( "devmap", SV_Map_f );
	Cmd_AddCommand( "spmap", SV_Map_f );
	Cmd_AddCommand( "spdevmap", SV_Map_f );
#endif
	Cmd_AddCommand( "loadgame", SV_LoadGame_f );
	Cmd_AddCommand( "killserver", SV_KillServer_f );
	if ( com_dedicated->integer ) {
		Cmd_AddCommand( "say", SV_ConSay_f );
	}
}

/*
==================
SV_RemoveOperatorCommands
==================
*/
void SV_RemoveOperatorCommands( void ) {
#if 0
	// removing these won't let the server start again
	Cmd_RemoveCommand( "heartbeat" );
	Cmd_RemoveCommand( "kick" );
	Cmd_RemoveCommand( "banUser" );
	Cmd_RemoveCommand( "banClient" );
	Cmd_RemoveCommand( "status" );
	Cmd_RemoveCommand( "serverinfo" );
	Cmd_RemoveCommand( "systeminfo" );
	Cmd_RemoveCommand( "dumpuser" );
	Cmd_RemoveCommand( "map_restart" );
	Cmd_RemoveCommand( "sectorlist" );
	Cmd_RemoveCommand( "say" );
#endif
}
