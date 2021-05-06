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

// sv_client.c -- server code for dealing with clients

#include "server.h"

#ifdef WIN32
#include <windows.h>
#endif

static void SV_CloseDownload( client_t *cl );

/*
=================
SV_GetChallenge

A "getchallenge" OOB command has been received
Returns a challenge number that can be used
in a subsequent connectResponse command.
We do this to prevent denial of service attacks that
flood the server with invalid connection IPs.  With a
challenge, they must give a valid IP address.

If we are authorizing, a challenge request will cause a packet
to be sent to the authorize server.

When an authorizeip is returned, a challenge response will be
sent to that ip.
=================
*/
void SV_GetChallenge( netadr_t from ) {
	int i;
	int oldest;
	int oldestTime;
	challenge_t *challenge;

	// ignore if we are in single player
	if ( SV_GameIsSinglePlayer() ) {
		return;
	}

	if ( SV_TempBanIsBanned( from ) ) {
		NET_OutOfBandPrint( NS_SERVER, from, "print\n%s\n", sv_tempbanmessage->string );
		return;
	}

	oldest = 0;
	oldestTime = 0x7fffffff;

	// see if we already have a challenge for this ip
	challenge = &svs.challenges[0];
	for ( i = 0 ; i < MAX_CHALLENGES ; i++, challenge++ ) {
		if ( !challenge->connected && NET_CompareAdr( from, challenge->adr ) ) {
			break;
		}
		if ( challenge->time < oldestTime ) {
			oldestTime = challenge->time;
			oldest = i;
		}
	}

	if ( i == MAX_CHALLENGES ) {
		// this is the first time this client has asked for a challenge
		challenge = &svs.challenges[oldest];

		challenge->challenge = ( ( rand() << 16 ) ^ rand() ) ^ svs.time;
		challenge->adr = from;
		challenge->firstTime = svs.time;
		challenge->firstPing = 0;
		challenge->time = svs.time;
		challenge->connected = qfalse;
		i = oldest;
	}

#if !defined( AUTHORIZE_SUPPORT )
	// FIXME: deal with restricted filesystem
	if ( 1 ) {
#else
	// if they are on a lan address, send the challengeResponse immediately
	if ( Sys_IsLANAddress( from ) ) {
#endif
		challenge->pingTime = svs.time;
		if ( sv_onlyVisibleClients->integer ) {
			NET_OutOfBandPrint( NS_SERVER, from, "challengeResponse %i %i", challenge->challenge, sv_onlyVisibleClients->integer );
		} else {
			NET_OutOfBandPrint( NS_SERVER, from, "challengeResponse %i", challenge->challenge );
		}
		return;
	}

#ifdef AUTHORIZE_SUPPORT
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

	// if they have been challenging for a long time and we
	// haven't heard anything from the authoirze server, go ahead and
	// let them in, assuming the id server is down
	if ( svs.time - challenge->firstTime > AUTHORIZE_TIMEOUT ) {
		Com_DPrintf( "authorize server timed out\n" );

		challenge->pingTime = svs.time;
		if ( sv_onlyVisibleClients->integer ) {
			NET_OutOfBandPrint( NS_SERVER, challenge->adr,
								"challengeResponse %i %i", challenge->challenge, sv_onlyVisibleClients->integer );
		} else {
			NET_OutOfBandPrint( NS_SERVER, challenge->adr,
								"challengeResponse %i", challenge->challenge );
		}

		return;
	}

	// otherwise send their ip to the authorize server
	if ( svs.authorizeAddress.type != NA_BAD ) {
		cvar_t  *fs;
		char game[1024];

		game[0] = 0;
		fs = Cvar_Get( "fs_game", "", CVAR_INIT | CVAR_SYSTEMINFO );
		if ( fs && fs->string[0] != 0 ) {
			strcpy( game, fs->string );
		}
		Com_DPrintf( "sending getIpAuthorize for %s\n", NET_AdrToString( from ) );
		fs = Cvar_Get( "sv_allowAnonymous", "0", CVAR_SERVERINFO );

		// NERVE - SMF - fixed parsing on sv_allowAnonymous
		NET_OutOfBandPrint( NS_SERVER, svs.authorizeAddress,
							"getIpAuthorize %i %i.%i.%i.%i %s %i",  svs.challenges[i].challenge,
							from.ip[0], from.ip[1], from.ip[2], from.ip[3], game, fs->integer );
	}
#endif // AUTHORIZE_SUPPORT
}

#ifdef AUTHORIZE_SUPPORT
/*
====================
SV_AuthorizeIpPacket

A packet has been returned from the authorize server.
If we have a challenge adr for that ip, send the
challengeResponse to it
====================
*/
void SV_AuthorizeIpPacket( netadr_t from ) {
	int challenge;
	int i;
	char    *s;
	char    *r;
	char ret[1024];

	if ( !NET_CompareBaseAdr( from, svs.authorizeAddress ) ) {
		Com_Printf( "SV_AuthorizeIpPacket: not from authorize server\n" );
		return;
	}

	challenge = atoi( Cmd_Argv( 1 ) );

	for ( i = 0 ; i < MAX_CHALLENGES ; i++ ) {
		if ( svs.challenges[i].challenge == challenge ) {
			break;
		}
	}
	if ( i == MAX_CHALLENGES ) {
		Com_Printf( "SV_AuthorizeIpPacket: challenge not found\n" );
		return;
	}

	// send a packet back to the original client
	svs.challenges[i].pingTime = svs.time;
	s = Cmd_Argv( 2 );
	r = Cmd_Argv( 3 );          // reason

	if ( !Q_stricmp( s, "ettest" ) ) {
		if ( Cvar_VariableValue( "fs_restrict" ) ) {
			// a demo client connecting to a demo server
			NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr,
								"challengeResponse %i", svs.challenges[i].challenge );
			return;
		}
		// they are a demo client trying to connect to a real server
		NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr, "print\nServer is not a demo server\n" );
		// clear the challenge record so it won't timeout and let them through
		memset( &svs.challenges[i], 0, sizeof( svs.challenges[i] ) );
		return;
	}
	if ( !Q_stricmp( s, "accept" ) ) {
		if ( sv_onlyVisibleClients->integer ) {
			NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr,
								"challengeResponse %i %i", svs.challenges[i].challenge, sv_onlyVisibleClients->integer );
		} else {
			NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr,
								"challengeResponse %i", svs.challenges[i].challenge );
		}
		return;
	}
	if ( !Q_stricmp( s, "unknown" ) ) {
		if ( !r ) {
			NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr, "print\nAwaiting CD key authorization\n" );
		} else {
			sprintf( ret, "print\n%s\n", r );
			NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr, ret );
		}
		// clear the challenge record so it won't timeout and let them through
		memset( &svs.challenges[i], 0, sizeof( svs.challenges[i] ) );
		return;
	}

	// authorization failed
	if ( !r ) {
		NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr, "print\nSomeone is using this CD Key\n" );
	} else {
		sprintf( ret, "print\n%s\n", r );
		NET_OutOfBandPrint( NS_SERVER, svs.challenges[i].adr, ret );
	}

	// clear the challenge record so it won't timeout and let them through
	memset( &svs.challenges[i], 0, sizeof( svs.challenges[i] ) );
}
#endif // AUTHORIZE_SUPPORT

/*
==================
SV_DirectConnect

A "connect" OOB command has been received
==================
*/
void SV_DirectConnect( netadr_t from ) {
	char userinfo[MAX_INFO_STRING];
	int i;
	client_t    *cl, *newcl;
	MAC_STATIC client_t temp;
	sharedEntity_t *ent;
	int clientNum;
	int version;
	int qport;
	int challenge;
	char        *password;
	int startIndex;
	char        *denied;
	int count;

	Com_DPrintf( "SVC_DirectConnect ()\n" );

	Q_strncpyz( userinfo, Cmd_Argv( 1 ), sizeof( userinfo ) );

	// DHM - Nerve :: Update Server allows any protocol to connect
	// NOTE TTimo: but we might need to store the protocol around for potential non http/ftp clients
	version = atoi( Info_ValueForKey( userinfo, "protocol" ) );
	if ( version != PROTOCOL_VERSION ) {
		NET_OutOfBandPrint( NS_SERVER, from, "print\n[err_prot]" PROTOCOL_MISMATCH_ERROR );
		Com_DPrintf( "    rejected connect from version %i\n", version );
		return;
	}

	challenge = atoi( Info_ValueForKey( userinfo, "challenge" ) );
	qport = atoi( Info_ValueForKey( userinfo, "qport" ) );

	if ( SV_TempBanIsBanned( from ) ) {
		NET_OutOfBandPrint( NS_SERVER, from, "print\n%s\n", sv_tempbanmessage->string );
		return;
	}

	// quick reject
	for ( i = 0,cl = svs.clients ; i < sv_maxclients->integer ; i++,cl++ ) {
		// DHM - Nerve :: This check was allowing clients to reconnect after zombietime(2 secs)
		//if ( cl->state == CS_FREE ) {
		//continue;
		//}
		if ( NET_CompareBaseAdr( from, cl->netchan.remoteAddress )
			 && ( cl->netchan.qport == qport
				  || from.port == cl->netchan.remoteAddress.port ) ) {
			if ( ( svs.time - cl->lastConnectTime )
				 < ( sv_reconnectlimit->integer * 1000 ) ) {
				Com_DPrintf( "%s:reconnect rejected : too soon\n", NET_AdrToString( from ) );
				return;
			}
			break;
		}
	}

	// see if the challenge is valid (local clients don't need to challenge)
	if ( !NET_IsLocalAddress( from ) ) {
		int ping;


		for ( i = 0 ; i < MAX_CHALLENGES ; i++ ) {
			if ( NET_CompareAdr( from, svs.challenges[i].adr ) ) {
				if ( challenge == svs.challenges[i].challenge ) {
					break;      // good
				}
			}
		}
		if ( i == MAX_CHALLENGES ) {
			NET_OutOfBandPrint( NS_SERVER, from, "print\n[err_dialog]No or bad challenge for address.\n" );
			return;
		}
		// force the IP key/value pair so the game can filter based on ip
		Info_SetValueForKey( userinfo, "ip", NET_AdrToString( from ) );

		if ( svs.challenges[i].firstPing == 0 ) {
			ping = svs.time - svs.challenges[i].pingTime;
			svs.challenges[i].firstPing = ping;
		} else {
			ping = svs.challenges[i].firstPing;
		}

		Com_Printf( "Client %i connecting with %i challenge ping\n", i, ping );
		svs.challenges[i].connected = qtrue;

		// never reject a LAN client based on ping
		if ( !Sys_IsLANAddress( from ) ) {
			if ( sv_minPing->value && ping < sv_minPing->value ) {
				NET_OutOfBandPrint( NS_SERVER, from, "print\n[err_dialog]Server is for high pings only\n" );
				Com_DPrintf( "Client %i rejected on a too low ping\n", i );
				return;
			}
			if ( sv_maxPing->value && ping > sv_maxPing->value ) {
				NET_OutOfBandPrint( NS_SERVER, from, "print\n[err_dialog]Server is for low pings only\n" );
				Com_DPrintf( "Client %i rejected on a too high ping: %i\n", i, ping );
				return;
			}
		}
	} else {
		// force the "ip" info key to "localhost"
		Info_SetValueForKey( userinfo, "ip", "localhost" );
	}

	newcl = &temp;
	memset( newcl, 0, sizeof( client_t ) );

	// if there is already a slot for this ip, reuse it
	for ( i = 0,cl = svs.clients ; i < sv_maxclients->integer ; i++,cl++ ) {
		if ( cl->state == CS_FREE ) {
			continue;
		}
		if ( NET_CompareBaseAdr( from, cl->netchan.remoteAddress )
			 && ( cl->netchan.qport == qport
				  || from.port == cl->netchan.remoteAddress.port ) ) {
			Com_Printf( "%s:reconnect\n", NET_AdrToString( from ) );
			newcl = cl;

			// this doesn't work because it nukes the players userinfo

//			// disconnect the client from the game first so any flags the
//			// player might have are dropped
//			VM_Call( gvm, GAME_CLIENT_DISCONNECT, newcl - svs.clients );
			//
			goto gotnewcl;
		}
	}

	// find a client slot
	// if "sv_privateClients" is set > 0, then that number
	// of client slots will be reserved for connections that
	// have "password" set to the value of "sv_privatePassword"
	// Info requests will report the maxclients as if the private
	// slots didn't exist, to prevent people from trying to connect
	// to a full server.
	// This is to allow us to reserve a couple slots here on our
	// servers so we can play without having to kick people.

	// check for privateClient password
	password = Info_ValueForKey( userinfo, "password" );
	if ( !strcmp( password, sv_privatePassword->string ) ) {
		startIndex = 0;
	} else {
		// skip past the reserved slots
		startIndex = sv_privateClients->integer;
	}

	newcl = NULL;
	for ( i = startIndex; i < sv_maxclients->integer ; i++ ) {
		cl = &svs.clients[i];
		if ( cl->state == CS_FREE ) {
			newcl = cl;
			break;
		}
	}

	if ( !newcl ) {
		if ( NET_IsLocalAddress( from ) ) {
			count = 0;
			for ( i = startIndex; i < sv_maxclients->integer ; i++ ) {
				cl = &svs.clients[i];
				if ( cl->netchan.remoteAddress.type == NA_BOT ) {
					count++;
				}
			}
			// if they're all bots
			if ( count >= sv_maxclients->integer - startIndex ) {
				SV_DropClient( &svs.clients[sv_maxclients->integer - 1], "only bots on server" );
				newcl = &svs.clients[sv_maxclients->integer - 1];
			} else {
				Com_Error( ERR_FATAL, "server is full on local connect\n" );
				return;
			}
		} else {
			NET_OutOfBandPrint( NS_SERVER, from, va( "print\n%s\n", sv_fullmsg->string ) );
			Com_DPrintf( "Rejected a connection.\n" );
			return;
		}
	}

	// we got a newcl, so reset the reliableSequence and reliableAcknowledge
	cl->reliableAcknowledge = 0;
	cl->reliableSequence = 0;

gotnewcl:
	for ( i = 0 ; i < 3 ; i++ ) {
		if ( newcl->savedPositions[i] ) {
			Z_Free( newcl->savedPositions[i] );
		}
	}

	// build a new connection
	// accept the new client
	// this is the only place a client_t is ever initialized
	*newcl = temp;
	clientNum = newcl - svs.clients;
	ent = SV_GentityNum( clientNum );
	newcl->gentity = ent;

	// save the challenge
	newcl->challenge = challenge;

	// save the address
	Netchan_Setup( NS_SERVER, &newcl->netchan, from, qport );
	// init the netchan queue

	if ( Cvar_VariableIntegerValue( "sv_replaceInvalidGuid" ) ) {
		char *cl_guid = Info_ValueForKey( userinfo, "cl_guid" );
		if ( strlen( cl_guid ) < 16 ) {
			byte *ip = newcl->netchan.remoteAddress.ip;
			Info_SetValueForKey( userinfo, "cl_guid", va( "%s %d.%d.%d.%d", Q_strupr( cl_guid ), ip[0], ip[1], ip[2], ip[3] ) );
		}
	}

	// save the userinfo
	Q_strncpyz( newcl->userinfo, userinfo, sizeof( newcl->userinfo ) );

	SV_NumberName( newcl );

	// get the game a chance to reject this connection or modify the userinfo
	denied = (char *)VM_Call( gvm, GAME_CLIENT_CONNECT, clientNum, qtrue, qfalse ); // firstTime = qtrue
	if ( denied ) {
		// we can't just use VM_ArgPtr, because that is only valid inside a VM_Call
		denied = VM_ExplicitArgPtr( gvm, (int)denied );

		NET_OutOfBandPrint( NS_SERVER, from, "print\n[err_dialog]%s\n", denied );
		Com_DPrintf( "Game rejected a connection: %s.\n", denied );
		return;
	}

	SV_UserinfoChanged( newcl );

	if ( newcl->netchan.remoteAddress.type != NA_BOT ) {
		if ( *sv_chatConnectedServers->string ) {
			SV_SendToChatConnectedServers( va( "rsay %s ^7connected to %s", newcl->name, sv_hostname->string ) );
		}
		if ( *sv_firstMessage->string ) {
			SV_SendServerCommand( newcl, "chat \"%s\"", sv_firstMessage->string );
		}

	}

	// DHM - Nerve :: Clear out firstPing now that client is connected
	svs.challenges[i].firstPing = 0;

	// send the connect packet to the client
	NET_OutOfBandPrint( NS_SERVER, from, "connectResponse" );

	Com_DPrintf( "Going from CS_FREE to CS_CONNECTED for %s\n", newcl->name );

	newcl->state = CS_CONNECTED;
	newcl->nextSnapshotTime = svs.time;
	newcl->lastPacketTime = svs.time;
	newcl->lastConnectTime = svs.time;

	// when we receive the first packet from the client, we will
	// notice that it is from a different serverid and that the
	// gamestate message was not just sent, forcing a retransmit
	newcl->gamestateMessageNum = -1;

	// if this was the first client on the server, or the last client
	// the server can hold, send a heartbeat to the master.
	count = 0;
	for ( i = 0,cl = svs.clients ; i < sv_maxclients->integer ; i++,cl++ ) {
		if ( svs.clients[i].state >= CS_CONNECTED ) {
			count++;
		}
	}
	if ( count == 1 || count == sv_maxclients->integer ) {
		SV_Heartbeat_f();
	}
	/*svs.lastPlayerLeftTime = 0x7FFFFFFF;
	svs.tempRestartTime = 0x7FFFFFFF - 600000;*/
}

/*
=====================
SV_DropClient

Called when the player is totally leaving the server, either willingly
or unwillingly.  This is NOT called if the entire server is quiting
or crashing -- SV_FinalCommand() will handle that
=====================
*/
void SV_DropClient( client_t *drop, const char *reason ) {
	int i, count = 0, bots = 0;
	challenge_t *challenge;
	qboolean isBot = qfalse;

	if ( drop->state == CS_ZOMBIE ) {
		return;     // already dropped
	}

	if ( drop->gentity && ( drop->gentity->r.svFlags & SVF_BOT ) ) {
		isBot = qtrue;
	} else {
		if ( drop->netchan.remoteAddress.type == NA_BOT ) {
			isBot = qtrue;
		}
	}

	if ( !isBot ) {
		// see if we already have a challenge for this ip
		challenge = &svs.challenges[0];

		for ( i = 0 ; i < MAX_CHALLENGES ; i++, challenge++ ) {
			if ( NET_CompareAdr( drop->netchan.remoteAddress, challenge->adr ) ) {
				challenge->connected = qfalse;
				break;
			}
		}

		// Kill any download
		SV_CloseDownload( drop );
	}

	if ( ( !SV_GameIsSinglePlayer() ) || ( !isBot ) ) {
		// tell everyone why they got dropped

		// Gordon: we want this displayed elsewhere now
		SV_SendServerCommand( NULL, "cpm \"%s" S_COLOR_WHITE " %s\n\"", drop->name, reason );
//		SV_SendServerCommand( NULL, "print \"[lof]%s" S_COLOR_WHITE " [lon]%s\n\"", drop->name, reason );
	}

	Com_DPrintf( "Going to CS_ZOMBIE for %s\n", drop->name );
	drop->state = CS_ZOMBIE;        // become free in a few seconds

	if ( drop->download ) {
		FS_FCloseFile( drop->download );
		drop->download = 0;
	}

	// call the prog function for removing a client
	// this will remove the body, among other things
	VM_Call( gvm, GAME_CLIENT_DISCONNECT, drop - svs.clients );

	// add the disconnect command
	SV_SendServerCommand( drop, "disconnect \"%s\"\n", reason );

	if ( drop->netchan.remoteAddress.type == NA_BOT ) {
		SV_BotFreeClient( drop - svs.clients );
	} else if ( *sv_chatConnectedServers->string ) {
		SV_SendToChatConnectedServers( va( "rsay %s ^7disconnected from %s", drop->name, sv_hostname->string ) );
	}

	// nuke user info
	SV_SetUserinfo( drop - svs.clients, "" );

	// if this was the last client on the server, send a heartbeat
	// to the master so it is known the server is empty
	// send a heartbeat now so the master will get up to date info
	// if there is already a slot for this ip, reuse it
	for ( i = 0 ; i < sv_maxclients->integer ; i++ ) {
		if ( svs.clients[i].state >= CS_CONNECTED ) {
			count++;
			if ( svs.clients[i].netchan.remoteAddress.type == NA_BOT ) {
				bots++;
			}
		}
	}
	if ( count == 0 ) {
		if ( !sv_pretendNonEmpty->integer ) {
			SV_Heartbeat_f();
		}

#ifdef WIN32
		// allow auto sleep
		SetThreadExecutionState( ES_CONTINUOUS );
#endif
	}
	if ( drop->netchan.remoteAddress.type != NA_BOT && count - bots == 0 ) {
		svs.lastPlayerLeftTime = 0x7FFFFFFF;
	}
}
/*
================
SV_SendClientGameState

Sends the first message from the server to a connected client.
This will be sent on the initial connection and upon each new map load.

It will be resent if the client acknowledges a later message but has
the wrong gamestate.
================
*/
void SV_SendClientGameState( client_t *client ) {
	int start;
	entityState_t   *base, nullstate;
	msg_t msg;
	byte msgBuffer[MAX_MSGLEN];


	Com_DPrintf( "SV_SendClientGameState() for %s\n", client->name );
	Com_DPrintf( "Going from CS_CONNECTED to CS_PRIMED for %s\n", client->name );
	client->state = CS_PRIMED;
	client->pureAuthentic = 0;
	client->gotCP = qfalse;

	// when we receive the first packet from the client, we will
	// notice that it is from a different serverid and that the
	// gamestate message was not just sent, forcing a retransmit
	client->gamestateMessageNum = client->netchan.outgoingSequence;

	MSG_Init( &msg, msgBuffer, sizeof( msgBuffer ) );

	// NOTE, MRE: all server->client messages now acknowledge
	// let the client know which reliable clientCommands we have received
	MSG_WriteLong( &msg, client->lastClientCommand );

	// send any server commands waiting to be sent first.
	// we have to do this cause we send the client->reliableSequence
	// with a gamestate and it sets the clc.serverCommandSequence at
	// the client side
	SV_UpdateServerCommandsToClient( client, &msg );

	// send the gamestate
	MSG_WriteByte( &msg, svc_gamestate );
	MSG_WriteLong( &msg, client->reliableSequence );

	// write the configstrings
	for ( start = 0 ; start < MAX_CONFIGSTRINGS ; start++ ) {
		if ( sv.configstrings[start][0] ) {
			MSG_WriteByte( &msg, svc_configstring );
			MSG_WriteShort( &msg, start );
			if ( sv_optionalPakNames->string[0] && start == CS_SYSTEMINFO && atoi( Info_ValueForKey( client->userinfo, "morepaks" ) ) ) {
				char referencedPakNames[BIG_INFO_STRING], referencedPaks[BIG_INFO_STRING];
				char newSysteminfo[BIG_INFO_STRING];
				
				strcpy( newSysteminfo, sv.configstrings[start] );
				FS_OptionalPaks( referencedPaks, referencedPakNames );
				Info_SetValueForKey_Big( newSysteminfo, "sv_referencedPaks", va( "%s %s", Cvar_VariableString( "sv_referencedPaks" ), referencedPaks ) );
				Info_SetValueForKey_Big( newSysteminfo, "sv_referencedPakNames", va( "%s %s", Cvar_VariableString( "sv_referencedPakNames"), referencedPakNames ) );

				MSG_WriteBigString( &msg, newSysteminfo );
			} else {
				MSG_WriteBigString( &msg, sv.configstrings[start] );
			}
		}
	}

	// write the baselines
	memset( &nullstate, 0, sizeof( nullstate ) );
	for ( start = 0 ; start < MAX_GENTITIES; start++ ) {
		base = &sv.svEntities[start].baseline;
		if ( !base->number ) {
			continue;
		}
		MSG_WriteByte( &msg, svc_baseline );
		MSG_WriteDeltaEntity( &msg, &nullstate, base, qtrue );
	}

	MSG_WriteByte( &msg, svc_EOF );

	MSG_WriteLong( &msg, client - svs.clients );

	// write the checksum feed
	MSG_WriteLong( &msg, sv.checksumFeed );

	// NERVE - SMF - debug info
	Com_DPrintf( "Sending %i bytes in gamestate to client: %i\n", msg.cursize, client - svs.clients );

	// deliver this to the client
	SV_SendMessageToClient( &msg, client );
}


/*
==================
SV_ClientEnterWorld
==================
*/
void SV_ClientEnterWorld( client_t *client, usercmd_t *cmd ) {
	int clientNum;
	sharedEntity_t *ent;

	Com_DPrintf( "Going from CS_PRIMED to CS_ACTIVE for %s\n", client->name );
	client->state = CS_ACTIVE;

	// set up the entity for the client
	clientNum = client - svs.clients;
	ent = SV_GentityNum( clientNum );
	ent->s.number = clientNum;
	client->gentity = ent;

	client->deltaMessage = -1;
	client->nextSnapshotTime = svs.time;    // generate a snapshot immediately
	client->lastUsercmd = *cmd;

	// call the game begin function
	VM_Call( gvm, GAME_CLIENT_BEGIN, client - svs.clients );
}

/*
============================================================

CLIENT COMMAND EXECUTION

============================================================
*/

/*
==================
SV_CloseDownload

clear/free any download vars
==================
*/
static void SV_CloseDownload( client_t *cl ) {
	int i;

	// EOF
	if ( cl->download ) {
		FS_FCloseFile( cl->download );
	}
	cl->download = 0;
	*cl->downloadName = 0;

	// Free the temporary buffer space
	for ( i = 0; i < MAX_DOWNLOAD_WINDOW; i++ ) {
		if ( cl->downloadBlocks[i] ) {
			Z_Free( cl->downloadBlocks[i] );
			cl->downloadBlocks[i] = NULL;
		}
	}

}

/*
==================
SV_StopDownload_f

Abort a download if in progress
==================
*/
void SV_StopDownload_f( client_t *cl ) {
	if ( *cl->downloadName ) {
		Com_DPrintf( "clientDownload: %d : file \"%s\" aborted\n", cl - svs.clients, cl->downloadName );
	}

	SV_CloseDownload( cl );
}

/*
==================
SV_DoneDownload_f

Downloads are finished
==================
*/
void SV_DoneDownload_f( client_t *cl ) {
	Com_DPrintf( "clientDownload: %s Done\n", cl->name );
	// resend the game state to update any clients that entered during the download
	SV_SendClientGameState( cl );
}

/*
==================
SV_NextDownload_f

The argument will be the last acknowledged block from the client, it should be
the same as cl->downloadClientBlock
==================
*/
void SV_NextDownload_f( client_t *cl ) {
	int block = atoi( Cmd_Argv( 1 ) );

	if ( block == cl->downloadClientBlock ) {
		Com_DPrintf( "clientDownload: %d : client acknowledge of block %d\n", cl - svs.clients, block );

		// Find out if we are done.  A zero-length block indicates EOF
		if ( cl->downloadBlockSize[cl->downloadClientBlock % MAX_DOWNLOAD_WINDOW] == 0 ) {
			Com_Printf( "clientDownload: %d : file \"%s\" completed\n", cl - svs.clients, cl->downloadName );
			SV_CloseDownload( cl );
			return;
		}

		cl->downloadSendTime = svs.time;
		cl->downloadClientBlock++;
		return;
	}
	// We aren't getting an acknowledge for the correct block, drop the client
	// FIXME: this is bad... the client will never parse the disconnect message
	//			because the cgame isn't loaded yet
	SV_DropClient( cl, "broken download" );
}

/*
==================
SV_BeginDownload_f
==================
*/
void SV_BeginDownload_f( client_t *cl ) {

	// Kill any existing download
	SV_CloseDownload( cl );

	//bani - stop us from printing dupe messages
	if ( strcmp( cl->downloadName, Cmd_Argv( 1 ) ) ) {
		cl->downloadnotify = DLNOTIFY_ALL;
	}

	// cl->downloadName is non-zero now, SV_WriteDownloadToClient will see this and open
	// the file itself
	Q_strncpyz( cl->downloadName, Cmd_Argv( 1 ), sizeof( cl->downloadName ) );
}

/*
==================
SV_WWWDownload_f
==================
*/
void SV_WWWDownload_f( client_t *cl ) {

	char *subcmd = Cmd_Argv( 1 );

	// only accept wwwdl commands for clients which we first flagged as wwwdl ourselves
	if ( !cl->bWWWDl ) {
		Com_Printf( "SV_WWWDownload: unexpected wwwdl '%s' for client '%s'\n", subcmd, cl->name );
		SV_DropClient( cl, va( "SV_WWWDownload: unexpected wwwdl %s", subcmd ) );
		return;
	}

	if ( !Q_stricmp( subcmd, "ack" ) ) {
		if ( cl->bWWWing ) {
			Com_Printf( "WARNING: dupe wwwdl ack from client '%s'\n", cl->name );
		}
		cl->bWWWing = qtrue;
		return;
	} else if ( !Q_stricmp( subcmd, "bbl8r" ) ) {
		SV_DropClient( cl, "acking disconnected download mode" );
		return;
	}

	// below for messages that only happen during/after download
	if ( !cl->bWWWing ) {
		Com_Printf( "SV_WWWDownload: unexpected wwwdl '%s' for client '%s'\n", subcmd, cl->name );
		SV_DropClient( cl, va( "SV_WWWDownload: unexpected wwwdl %s", subcmd ) );
		return;
	}

	if ( !Q_stricmp( subcmd, "done" ) ) {
		cl->download = 0;
		*cl->downloadName = 0;
		cl->bWWWing = qfalse;
		return;
	} else if ( !Q_stricmp( subcmd, "fail" ) )        {
		cl->download = 0;
		*cl->downloadName = 0;
		cl->bWWWing = qfalse;
		cl->bFallback = qtrue;
		// send a reconnect
		SV_SendClientGameState( cl );
		return;
	} else if ( !Q_stricmp( subcmd, "chkfail" ) )        {
		Com_Printf( "WARNING: client '%s' reports that the redirect download for '%s' had wrong checksum.\n", cl->name, cl->downloadName );
		Com_Printf( "         you should check your download redirect configuration.\n" );
		cl->download = 0;
		*cl->downloadName = 0;
		cl->bWWWing = qfalse;
		cl->bFallback = qtrue;
		// send a reconnect
		SV_SendClientGameState( cl );
		return;
	}

	Com_Printf( "SV_WWWDownload: unknown wwwdl subcommand '%s' for client '%s'\n", subcmd, cl->name );
	SV_DropClient( cl, va( "SV_WWWDownload: unknown wwwdl subcommand '%s'", subcmd ) );
}


void SV_ListMaps( client_t *cl ) {
	int nextTime;

	if ( cl->nextMaplistTime + 5000 >= cl->nextFindmapTime + 1000 ) {
		nextTime = cl->nextMaplistTime + 5000;
	} else {
		nextTime = cl->nextFindmapTime + 1000;
	}
	if ( nextTime > svs.time ) {
		int sec = ( int )ceil( ( double )( nextTime - svs.time ) / 1000 );

		SV_SendServerCommand( cl, sec == 1 ? "print \"^3listmaps: ^7Wait %d second to use again\n\"" : "print \"^3listmaps: ^7Wait %d seconds to use again\n\"", sec );
		return;
	}

	if ( sv_allowListmaps->integer != 0 ) {
		char outString[10240];
		char buf[999];
		char unlistMaps[128][MAX_QPATH];
		int numUnlistMaps;
		int length, retColumn, argc;
		int i;

		Cmd_TokenizeString( sv_unlistedMapNames->string );
		for ( i = 0 ; i < Cmd_Argc() ; i++ ) {
			Q_strncpyz( unlistMaps[i], Cmd_Argv( i ), sizeof( unlistMaps[i] ) );
			Q_strlwr( unlistMaps[i] );
		}
		numUnlistMaps = i;

		Cmd_TokenizeString( sv_mapNames->string );
		outString[0] = 0;
		retColumn = 2;
		argc = Cmd_Argc();
		for ( i = 0 ; i < argc ; i++ ) {
			char *argv = Cmd_Argv( i );
			int j;
			qboolean flag = qfalse;

			for ( j = 0 ; j < numUnlistMaps ; j++ ) {
				if ( strcmp( argv, unlistMaps[j] ) == 0 ) {
					flag = qtrue;
				}
			}

			if ( flag ) {
				retColumn = ( retColumn + 1 ) % 3;
			} else if ( i % 3 == retColumn || i == argc - 1 || strlen( argv ) > 26 ) {
				Q_strcat( outString, sizeof( outString ), va( "%s\n", argv ) );
				retColumn = i % 3;
			} else {
				char buf[29];

				Q_strncpyz( buf, "                                                  ", sizeof( buf ) - strlen( argv ) );
				Q_strcat( outString, sizeof( outString ), va( "%s%s", argv, buf ) );
			}
		}

		length = strlen( outString );
		if ( length > ( sizeof ( buf ) - 1 ) * 10 ) {
			Q_strncpyz( outString, sv_mapNames->string, sizeof( outString ) );
			Q_strcat( outString, sizeof( outString ), "\n" );
			length = strlen( outString );
		}

		for ( i = 0 ; i < length ; i += sizeof( buf ) - 1 ) {
			Q_strncpyz( buf, &outString[i], sizeof( buf ) );
			SV_SendServerCommand( cl, "print \"%s\"", buf );
		}
		cl->nextMaplistTime = svs.time + 25000;
		cl->nextFindmapTime = svs.time + 2000;
	} else {
		SV_SendServerCommand( cl, "print \"Sorry, ^3listmaps ^7is disabled\n\"");
	}
}

void SV_MapList( client_t *cl ) {
	if ( cl->nextMaplistTime > svs.time || cl->nextFindmapTime > svs.time ) {
		int nt = cl->nextMaplistTime >= cl->nextFindmapTime ? cl->nextMaplistTime : cl->nextFindmapTime;
		int sec = ( int )ceil( ( double )( nt - svs.time ) / 1000 );

		SV_SendServerCommand( cl, sec == 1 ? "print \"^3maplist: ^7Wait %d second to use again\n\"" : "print \"^3maplist: ^7Wait %d seconds to use again\n\"", sec );
		return;
	}

	if ( sv_allowListmaps->integer != 0 ) {
		int i, length = strlen( sv_mapNames->string );
		char buf[999];

		for ( i = 0 ; i < length ; i += sizeof( buf ) - 1 ) {
			Q_strncpyz( buf, &sv_mapNames->string[i], sizeof( buf ) );
			SV_SendServerCommand( cl, "print \"%s\"", buf );
		}
		SV_SendServerCommand( cl, "print \"\n\"");

		cl->nextMaplistTime = svs.time + 20000;
		cl->nextFindmapTime = svs.time + 1000;
	} else {
		SV_SendServerCommand( cl, "print \"Sorry, ^3listmaps ^7is disabled\n\"");
	}
}

static void SV_ListMaps_f( client_t *cl ) {
	if ( cl->nextServercommandTime > svs.time ) {
		return;
	} 
	cl->nextServercommandTime = svs.time + 200;

	SV_ListMaps( cl );
}

static void SV_MapList_f( client_t *cl ) {
	if ( cl->nextServercommandTime > svs.time ) {
		return;
	} 

	cl->nextServercommandTime = svs.time + 200;
	SV_MapList( cl );
}

void SV_FindMap( client_t *cl, int start ) {
	char args[16][MAX_QPATH];
	int argc;
	char *matches[64];
	int index = 0;
	int retColumn;
	int i;

	if ( cl ) {
		if ( cl->nextFindmapTime > svs.time ) {
			int sec = ( int )ceil( ( double )( cl->nextFindmapTime - svs.time ) / 1000 );
			SV_SendServerCommand( cl, sec == 1 ? "print \"^3findmap: ^7Wait %d second to use again\n\"" : "print \"^3findmap: ^7Wait %d seconds to use again\n\"", sec );
			return;
		}
	}

	argc = Cmd_Argc();

	if ( sv_allowListmaps->integer == 0 ) {
		SV_SendServerCommand( cl, "print \"Sorry, ^3findmap ^7is disabled\n\"");
		return;
	} else if ( argc < 2 ) {
		SV_SendServerCommand( cl, "print \"^3usage: ^7\\findmap <keywords>\n\"" );
		return;
	} else if ( argc > sizeof( args ) / sizeof( args[0] ) ) {
		SV_SendServerCommand( cl, "print \"^3findmap: ^7Too many keywords\n\"" );
		return;
	}

	for ( i = 0 ; i < argc ; i++ ) {
		Q_strncpyz( args[i], Cmd_Argv( i ), sizeof( args[i] ) );
		Q_strlwr( args[i] );
	}

	Cmd_TokenizeString( sv_mapNames->string );

	for ( i = 0 ; i < Cmd_Argc() ; i++ ) {
		char *p = Cmd_Argv( i );
		qboolean match;
		int j;

		match = qtrue;
		for ( j = start ; j < argc ; j++ ) {
			if ( strstr( p, args[j] ) == NULL ) {
				match = qfalse;
				break;
			}
		}
		if ( match ) {
			if ( index >= sizeof( matches ) / sizeof( matches[0] ) ) {
				if ( cl ) {
					SV_SendServerCommand( cl, "print \"^3findmap: ^7Too many matches\n\"" );
				} else {
					Cvar_Set( "returnvalue", "^3findmap: ^7Too many matches" );
				}
				return;
			}
			matches[index] = p;
			index++;
		}
	}

	if ( cl ) {
		char outString[2048];

		outString[0] = '\0';
		retColumn = 2;
		for ( i = 0 ; i < index ; i++ ) {
			if ( i % 3 == retColumn || i == index - 1 || strlen( matches[i] ) > 26 ) {
				Q_strcat( outString, sizeof( outString ), va( "%s\n", matches[i] ) );
				retColumn = i % 3;
			} else {
				char buf[29];

				Q_strncpyz( buf, "                                                  ", sizeof( buf ) - strlen( matches[i] ) );
				Q_strcat( outString, sizeof( outString ), va( "%s%s", matches[i], buf ) );
			}
		}
		if ( i == 0 ) {
			SV_SendServerCommand( cl, "print \"^3findmap: ^7Map not found\n\"" );
			return;
		}

		if ( strlen( outString ) >= sizeof( outString ) ) {
			Com_Error( ERR_FATAL, "SV_FindMap_f: outString overflowed" );
		} else if ( strlen( outString ) == sizeof( outString ) - 1 ) {
			SV_SendServerCommand( cl, "print \"^3findmap: ^7Too many matches\n\"" );
			return;
		} else {
			int length = strlen( outString );
			char buf[999];

			if ( length >= sizeof( buf ) ) {
				SV_SendServerCommand( cl, "print \"^3findmap: ^7Too many matches\n\"" );
				return;
			}
			for ( i = 0 ; i < length ; i += sizeof( buf ) - 1 ) {
				Q_strncpyz( buf, &outString[i], sizeof( buf ) );
				SV_SendServerCommand( cl, "print \"%s\"", buf );
			}
			cl->nextFindmapTime = svs.time + 1000;
		}
	} else {
		char outString[256];

		if ( index == 0 ) {
			Cvar_Set( "returnvalue", "^3findmap: ^7Map not found" );
			return;
		}

		outString[0] = '\0';
		for ( i = 0 ; i < index ; i++ ) {
			if ( i > 0 ) {
				Q_strcat( outString, sizeof( outString ), " " );
			}
			if ( strlen( outString ) + strlen( matches[i] ) >= sizeof( outString ) ) {
				Cvar_Set( "returnvalue", "^3findmap: ^7Too many matches" );
				return;
			}
			Q_strcat( outString, sizeof( outString ), matches[i] );
		}

		Cvar_Set( "returnvalue", outString );
	}
}

static void SV_FindMap_f( client_t *cl ) {
	if ( cl->nextServercommandTime > svs.time ) {
		return;
	}
	cl->nextServercommandTime = svs.time + 200;

	SV_FindMap( cl, 1 );
}

void SV_SetFindMapTime( int clientNum, int time ) {
	if ( clientNum >= 0 && clientNum < MAX_CLIENTS ) {
		if ( svs.time + time > svs.clients[clientNum].nextFindmapTime ) {
			if ( time >= 30000 ) {
				svs.clients[clientNum].nextFindmapTime = svs.time + 30000;
			} else {
				svs.clients[clientNum].nextFindmapTime = svs.time + time;
			}
		}
	}
}

static void SV_SendInfo( client_t *cl, const char *info, qboolean chatCmd ) {
	if ( chatCmd ) {
		char buf[1024];
		char *p;

		Q_strncpyz( buf, info, sizeof( buf ) );
		p = strtok( buf, "\n" );
		while ( p ) {
			SV_SendServerCommand( NULL, "chat \"%s\"", p );
			p = strtok( NULL, "\n" );
		}
	} else {
		SV_SendServerCommand( cl, "print \"%s\n\"", info );
	}
}

void SV_MapInfo_f( client_t *cl ){
	fileHandle_t fp;
	long len;
	char buf[4096];
	char pakBasename[MAX_OSPATH];
	char args[16][MAX_QPATH];
	char targetMap[MAX_QPATH] = "";
	int argc = Cmd_Argc();
	char *cmd = Cmd_Argv(0);
	qboolean chatCmd;

	if ( cmd[0] == '!' || cmd[0] == '/' || cmd[0] == '\\' ) {
		chatCmd = qtrue;
	} else {
		chatCmd = qfalse;
	}
	if ( cl ) {
		if ( !sv_allowListmaps->integer ) {
			SV_SendInfo( cl, "Sorry, ^3mapinfo ^7is disabled", chatCmd );
			return;
		}
		if ( cl->nextFindmapTime > svs.time ) {
			int sec = ( int )ceil( ( double )( cl->nextFindmapTime - svs.time ) / 1000 );
			SV_SendServerCommand( cl, "print \"^3mapinfo: ^7wait %d %s to use again\n\"", sec, sec == 1 ? "second" : "seconds" );
			return;
		}
		cl->nextFindmapTime = svs.time + 1000;
	}

	if ( argc > sizeof( args ) / sizeof( args[0] ) ) {
		SV_SendInfo( cl, "Too many keywords.", chatCmd );
		return;
	}
	if ( argc == 1 ) {
		Q_strncpyz( targetMap, sv_mapname->string, sizeof( targetMap ) );
	} else {
		char *matches[64];
		int i, index = 0;

		for ( i = 0 ; i < argc ; i++ ) {
			Q_strncpyz( args[i], Cmd_Argv( i ), sizeof( args[i] ) );
			Q_strlwr( args[i] );
		}

		Cmd_TokenizeString( sv_mapNames->string );

		for ( i = 0 ; i < Cmd_Argc() ; i++ ) {
			char *p = Cmd_Argv( i );
			qboolean match;
			int j;

			if ( argc == 2 && !strcmp( args[1], p ) ) {
				matches[0] = p;
				index = 1;
				break;
			}

			match = qtrue;
			for ( j = 1 ; j < argc ; j++ ) {
				if ( strstr( p, args[j] ) == NULL ) {
					match = qfalse;
					break;
				}
			}
			if ( match ) {
				if ( index >= sizeof( matches ) / sizeof( matches[0] ) ) {
					SV_SendInfo( cl, "^7Too many matches.", chatCmd );
					return;
				}
				matches[index] = p;
				index++;
			}
		}
		if ( index == 1 ) {
			Q_strncpyz( targetMap, matches[0], sizeof( targetMap ) );
		} else if ( index < 1 ) {
			SV_SendInfo( cl, "Map not found.", chatCmd );
			return;
		} else {
			char outString[256];

			outString[0] = '\0';
			for ( i = 0 ; i < index ; i++ ) {
				if ( i > 0 ) {
					Q_strcat( outString, sizeof( outString ), " " );
				}
				if ( strlen( outString ) + strlen( matches[i] ) >= sizeof( outString ) ) {
					SV_SendInfo( cl, "Too many matches.", chatCmd );
					return;
				}
				Q_strcat( outString, sizeof( outString ), matches[i] );
			}
			SV_SendInfo( cl, outString, chatCmd );
			return;
		}
	}
	
	len = FS_PakInfoForFile( va( "maps/%s.bsp", targetMap ), pakBasename );
	if ( len > 0 ) {
		char *sizeInText;

		if ( len >= 1024*1024 ) {
			sizeInText = va ( "%.2fMB", ( double )len / 1024 / 1024 );
		} else {
			sizeInText = va ( "%dKB", len / 1024 );
		}
		SV_SendInfo( cl, va ( "^zpk3^7: %s.pk3  %s", pakBasename, sizeInText ), chatCmd );
	}

	if ( FS_FOpenFileRead( va( "scripts/%s.arena", targetMap ), &fp, qfalse ) > 0 ) {
		if ( FS_Read( buf, sizeof( buf ), fp ) ) {
			int i;
			char *map = "", *longname = "", *description = "";

			Cmd_TokenizeString( buf );
			for ( i = 1; i < Cmd_Argc(); i++ ) {
				char *argv = Cmd_Argv( i );

				if ( !Q_stricmp( argv, "map" ) ) {
					if ( ++i >= Cmd_Argc() )
						break;
					map = Cmd_Argv( i );
				} else if ( !Q_stricmp( argv, "longname" ) ) {
					if ( ++i >= Cmd_Argc() )
						break;
					longname = Cmd_Argv( i );
				} else if ( !Q_stricmp( argv, "briefing" ) ) {
					if ( ++i >= Cmd_Argc() )
						break;
					description = Cmd_Argv( i );
				}
			}
			if ( Q_stricmp( map, targetMap ) ) {
				map = targetMap;
			}
			for ( i = 0 ; description[i] ; i++ ) {
				if ( description[i] == '^' ) {
					if ( !description[++i] ) {
						break;
					} else {
						continue;
					}
				}
				if ( description[i] == '*' ) {
					description[i] = ' ';
				}
			}
			SV_SendInfo( cl, va( "^3map^7: %s  ^3longname^7: %s\n%s", map, longname, description ), chatCmd );
			FS_FCloseFile( fp );
		}
	} else {
		SV_SendInfo( cl, va ( "map^7: %s", targetMap ), chatCmd );
	}
}

void SV_CV_f( client_t *cl ) {
	Cmd_TokenizeString( va( "callvote %s", Cmd_Args() ) );
	if ( sv.state == SS_GAME ) {
		VM_Call( gvm, GAME_CLIENT_COMMAND, cl - svs.clients );
	}
}

void SV_UserFeedback_f(client_t* cl) {
	char *cmd = Cmd_Argv(0);
	char *feedback = Cmd_ArgsFrom(1);
	qboolean chatCmd;
	fileHandle_t fh;
	time_t t;
	struct tm *lt;
	char dateTime[64];
	char userinfo[MAX_INFO_STRING];

	if ( cl->nextServercommandTime > svs.time ) {
		return;
	}
	cl->nextServercommandTime = svs.time + 200;

	if ( cmd[0] == '!' || cmd[0] == '/' || cmd[0] == '\\') {
		chatCmd = qtrue;
	} else {
		chatCmd = qfalse;
	}

	if ( !sv_allowUserFeedbacks->integer ) {
		SV_SendInfo( cl, "Sorry, ^3feedback ^7is disabled", chatCmd );
		return;
	}
	if ( cl->nextFeedbackTime > svs.time ) {
		int sec = ( int )ceil( ( double )( cl->nextFeedbackTime - svs.time ) / 1000 );
		SV_SendServerCommand( cl, "print \"^3feedback: ^7wait %d %s to use again\n\"", sec, sec == 1 ? "second" : "seconds" );
		return;
	}
	cl->nextFeedbackTime = svs.time + 1000;

	if (!feedback[0]) {
		if (chatCmd) {
			SV_SendServerCommand(cl, "chat \"usage: !feedback [messages to admin]\"");
		}
		else {
			SV_SendServerCommand(cl, "print \"usage: \\feedback [messages to admin]\n\"");
		}
		return;
	}

	if (time(&t)) {
		lt = localtime(&t);
		strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", lt);
	}
	else {
		Q_strncpyz(dateTime, "Time stamp unavailable:", sizeof(dateTime));
	}
	SV_GetUserinfo(cl - svs.clients, userinfo, sizeof(userinfo));
	if (FS_AppendTextToFile("UserFeedbacks.txt", va("%s %s (%s %s): %s\n", dateTime,
		cl->name, Info_ValueForKey(userinfo, "ip"), Info_ValueForKey(userinfo, "cl_guid"), Cmd_ArgsFrom(1)))) {
		if (chatCmd) {
			SV_SendServerCommand(cl, "chat \"^8Thank you for your feedback.\"");
		}
		else {
			SV_SendServerCommand(cl, "print \"^2Thank you for your feedback.\n\"");
		}
	}
	else {
		if (chatCmd) {
			SV_SendServerCommand(cl, "chat \"^3Oops, failed to write feedback to file...\"");
		}
		else {
			SV_SendServerCommand(cl, "print \"^3Oops, failed to write feedback to file...\n\"");
		}
	}
}

// abort an attempted download
void SV_BadDownload( client_t *cl, msg_t *msg ) {
	MSG_WriteByte( msg, svc_download );
	MSG_WriteShort( msg, 0 ); // client is expecting block zero
	MSG_WriteLong( msg, -1 ); // illegal file size

	*cl->downloadName = 0;
}

/*
==================
SV_CheckFallbackURL

sv_wwwFallbackURL can be used to redirect clients to a web URL in case direct ftp/http didn't work (or is disabled on client's end)
return true when a redirect URL message was filled up
when the cvar is set to something, the download server will effectively never use a legacy download strategy
==================
*/
static qboolean SV_CheckFallbackURL( client_t *cl, msg_t *msg ) {
	if ( !sv_wwwFallbackURL->string || strlen( sv_wwwFallbackURL->string ) == 0 ) {
		return qfalse;
	}

	Com_Printf( "clientDownload: sending client '%s' to fallback URL '%s'\n", cl->name, sv_wwwFallbackURL->string );

	MSG_WriteByte( msg, svc_download );
	MSG_WriteShort( msg, -1 ); // block -1 means ftp/http download
	MSG_WriteString( msg, sv_wwwFallbackURL->string );
	MSG_WriteLong( msg, 0 );
	MSG_WriteLong( msg, 2 ); // DL_FLAG_URL

	return qtrue;
}

/*
==================
SV_WriteDownloadToClient

Check to see if the client wants a file, open it if needed and start pumping the client
Fill up msg with data
==================
*/
void SV_WriteDownloadToClient( client_t *cl, msg_t *msg ) {
	int curindex;
	int rate;
	int blockspersnap;
	int idPack;
	char errorMessage[1024];
	int download_flag;

	qboolean bTellRate = qfalse; // verbosity

	if ( !*cl->downloadName ) {
		return; // Nothing being downloaded

	}
	if ( cl->bWWWing ) {
		return; // The client acked and is downloading with ftp/http

	}
	// CVE-2006-2082
	// validate the download against the list of pak files
	if ( !FS_VerifyPak( cl->downloadName ) ) {
		// will drop the client and leave it hanging on the other side. good for him
		SV_DropClient( cl, "illegal download request" );
		return;
	}

	if ( !cl->download ) {
		// We open the file here

		//bani - prevent duplicate download notifications
		if ( cl->downloadnotify & DLNOTIFY_BEGIN ) {
			cl->downloadnotify &= ~DLNOTIFY_BEGIN;
			Com_Printf( "clientDownload: %d : beginning \"%s\"\n", cl - svs.clients, cl->downloadName );
		}

		idPack = FS_idPak( cl->downloadName, BASEGAME );

		// sv_allowDownload and idPack checks
		if ( !sv_allowDownload->integer || idPack ) {
			// cannot auto-download file
			if ( idPack ) {
				Com_Printf( "clientDownload: %d : \"%s\" cannot download id pk3 files\n", cl - svs.clients, cl->downloadName );
				Com_sprintf( errorMessage, sizeof( errorMessage ), "Cannot autodownload official pk3 file \"%s\"", cl->downloadName );
			} else {
				Com_Printf( "clientDownload: %d : \"%s\" download disabled", cl - svs.clients, cl->downloadName );
				if ( sv_pure->integer ) {
					Com_sprintf( errorMessage, sizeof( errorMessage ), "Could not download \"%s\" because autodownloading is disabled on the server.\n\n"
																	   "You will need to get this file elsewhere before you "
																	   "can connect to this pure server.\n", cl->downloadName );
				} else {
					Com_sprintf( errorMessage, sizeof( errorMessage ), "Could not download \"%s\" because autodownloading is disabled on the server.\n\n"
																	   "Set autodownload to No in your settings and you might be "
																	   "able to connect even if you don't have the file.\n", cl->downloadName );
				}
			}

			SV_BadDownload( cl, msg );
			MSG_WriteString( msg, errorMessage ); // (could SV_DropClient isntead?)

			return;
		}

		// www download redirect protocol
		// NOTE: this is called repeatedly while a client connects. Maybe we should sort of cache the message or something
		// FIXME: we need to abstract this to an independant module for maximum configuration/usability by server admins
		// FIXME: I could rework that, it's crappy
		if ( sv_wwwDownload->integer ) {
			if ( cl->bDlOK ) {
				if ( !cl->bFallback ) {
					fileHandle_t handle;
					int downloadSize = FS_SV_FOpenFileRead( cl->downloadName, &handle );
					if ( downloadSize ) {
						FS_FCloseFile( handle ); // don't keep open, we only care about the size

						Q_strncpyz( cl->downloadURL, va( "%s/%s", sv_wwwBaseURL->string, cl->downloadName ), sizeof( cl->downloadURL ) );

						//bani - prevent multiple download notifications
						if ( cl->downloadnotify & DLNOTIFY_REDIRECT ) {
							cl->downloadnotify &= ~DLNOTIFY_REDIRECT;
							Com_Printf( "Redirecting client '%s' to %s\n", cl->name, cl->downloadURL );
						}
						// once cl->downloadName is set (and possibly we have our listening socket), let the client know
						cl->bWWWDl = qtrue;
						MSG_WriteByte( msg, svc_download );
						MSG_WriteShort( msg, -1 ); // block -1 means ftp/http download
						// compatible with legacy svc_download protocol: [size] [size bytes]
						// download URL, size of the download file, download flags
						MSG_WriteString( msg, cl->downloadURL );
						MSG_WriteLong( msg, downloadSize );
						download_flag = 0;
						if ( sv_wwwDlDisconnected->integer ) {
							download_flag |= ( 1 << DL_FLAG_DISCON );
						}
						MSG_WriteLong( msg, download_flag ); // flags
						return;
					} else {
						// that should NOT happen - even regular download would fail then anyway
						Com_Printf( "ERROR: Client '%s': couldn't extract file size for %s\n", cl->name, cl->downloadName );
					}
				} else {
					cl->bFallback = qfalse;
					if ( SV_CheckFallbackURL( cl, msg ) ) {
						return;
					}
					Com_Printf( "Client '%s': falling back to regular downloading for failed file %s\n", cl->name, cl->downloadName );
				}
			} else {
				if ( SV_CheckFallbackURL( cl, msg ) ) {
					return;
				}
				Com_Printf( "Client '%s' is not configured for www download\n", cl->name );
			}
		}

		// find file
		cl->bWWWDl = qfalse;
		cl->downloadSize = FS_SV_FOpenFileRead( cl->downloadName, &cl->download );
		if ( cl->downloadSize <= 0 ) {
			Com_Printf( "clientDownload: %d : \"%s\" file not found on server\n", cl - svs.clients, cl->downloadName );
			Com_sprintf( errorMessage, sizeof( errorMessage ), "File \"%s\" not found on server for autodownloading.\n", cl->downloadName );
			SV_BadDownload( cl, msg );
			MSG_WriteString( msg, errorMessage ); // (could SV_DropClient isntead?)
			return;
		}

		// is valid source, init
		cl->downloadCurrentBlock = cl->downloadClientBlock = cl->downloadXmitBlock = 0;
		cl->downloadCount = 0;
		cl->downloadEOF = qfalse;

		bTellRate = qtrue;
	}

	// Perform any reads that we need to
	while ( cl->downloadCurrentBlock - cl->downloadClientBlock < MAX_DOWNLOAD_WINDOW &&
			cl->downloadSize != cl->downloadCount ) {

		curindex = ( cl->downloadCurrentBlock % MAX_DOWNLOAD_WINDOW );

		if ( !cl->downloadBlocks[curindex] ) {
			cl->downloadBlocks[curindex] = Z_Malloc( MAX_DOWNLOAD_BLKSIZE );
		}

		cl->downloadBlockSize[curindex] = FS_Read( cl->downloadBlocks[curindex], MAX_DOWNLOAD_BLKSIZE, cl->download );

		if ( cl->downloadBlockSize[curindex] < 0 ) {
			// EOF right now
			cl->downloadCount = cl->downloadSize;
			break;
		}

		cl->downloadCount += cl->downloadBlockSize[curindex];

		// Load in next block
		cl->downloadCurrentBlock++;
	}

	// Check to see if we have eof condition and add the EOF block
	if ( cl->downloadCount == cl->downloadSize &&
		 !cl->downloadEOF &&
		 cl->downloadCurrentBlock - cl->downloadClientBlock < MAX_DOWNLOAD_WINDOW ) {

		cl->downloadBlockSize[cl->downloadCurrentBlock % MAX_DOWNLOAD_WINDOW] = 0;
		cl->downloadCurrentBlock++;

		cl->downloadEOF = qtrue;  // We have added the EOF block
	}

	// Loop up to window size times based on how many blocks we can fit in the
	// client snapMsec and rate

	// based on the rate, how many bytes can we fit in the snapMsec time of the client
	// normal rate / snapshotMsec calculation
	rate = cl->rate;

	// show_bug.cgi?id=509
	// for autodownload, we use a seperate max rate value
	// we do this everytime because the client might change it's rate during the download
	if ( sv_dl_maxRate->integer < rate ) {
		rate = sv_dl_maxRate->integer;
		if ( bTellRate ) {
			Com_Printf( "'%s' downloading at sv_dl_maxrate (%d)\n", cl->name, sv_dl_maxRate->integer );
		}
	} else
	if ( bTellRate ) {
		Com_Printf( "'%s' downloading at rate %d\n", cl->name, rate );
	}

	if ( !rate ) {
		blockspersnap = 1;
	} else {
		blockspersnap = ( ( rate * cl->snapshotMsec ) / 1000 + MAX_DOWNLOAD_BLKSIZE ) /
						MAX_DOWNLOAD_BLKSIZE;
	}

	if ( blockspersnap < 0 ) {
		blockspersnap = 1;
	}

	while ( blockspersnap-- ) {

		// Write out the next section of the file, if we have already reached our window,
		// automatically start retransmitting

		if ( cl->downloadClientBlock == cl->downloadCurrentBlock ) {
			return; // Nothing to transmit

		}
		if ( cl->downloadXmitBlock == cl->downloadCurrentBlock ) {
			// We have transmitted the complete window, should we start resending?

			//FIXME:  This uses a hardcoded one second timeout for lost blocks
			//the timeout should be based on client rate somehow
			if ( svs.time - cl->downloadSendTime > 1000 ) {
				cl->downloadXmitBlock = cl->downloadClientBlock;
			} else {
				return;
			}
		}

		// Send current block
		curindex = ( cl->downloadXmitBlock % MAX_DOWNLOAD_WINDOW );

		MSG_WriteByte( msg, svc_download );
		MSG_WriteShort( msg, cl->downloadXmitBlock );

		// block zero is special, contains file size
		if ( cl->downloadXmitBlock == 0 ) {
			MSG_WriteLong( msg, cl->downloadSize );
		}

		MSG_WriteShort( msg, cl->downloadBlockSize[curindex] );

		// Write the block
		if ( cl->downloadBlockSize[curindex] ) {
			MSG_WriteData( msg, cl->downloadBlocks[curindex], cl->downloadBlockSize[curindex] );
		}

		Com_DPrintf( "clientDownload: %d : writing block %d\n", cl - svs.clients, cl->downloadXmitBlock );

		// Move on to the next block
		// It will get sent with next snap shot.  The rate will keep us in line.
		cl->downloadXmitBlock++;

		cl->downloadSendTime = svs.time;
	}
}

/*
=================
SV_Disconnect_f

The client is going to disconnect, so remove the connection immediately  FIXME: move to game?
=================
*/
static void SV_Disconnect_f( client_t *cl ) {
	SV_DropClient( cl, "disconnected" );
}

/*
=================
SV_VerifyPaks_f

If we are pure, disconnect the client if they do no meet the following conditions:

1. the first two checksums match our view of cgame and ui DLLs
   Wolf specific: the checksum is the checksum of the pk3 we found the DLL in
2. there are no any additional checksums that we do not have

This routine would be a bit simpler with a goto but i abstained

=================
*/
static void SV_VerifyPaks_f( client_t *cl ) {
	int nChkSum1, nChkSum2, nClientPaks, nServerPaks, i, j, nCurArg;
	//int nClientChkSum[1024];
	int nServerChkSum[1024];
	const char *pPaks, *pArg;
	qboolean bGood = qtrue;

	// if we are pure, we "expect" the client to load certain things from
	// certain pk3 files, namely we want the client to have loaded the
	// ui and cgame that we think should be loaded based on the pure setting
	if ( sv_pure->integer != 0 ) {

		bGood = qtrue;
		nChkSum1 = nChkSum2 = 0;

		bGood = ( FS_FileIsInPAK( FS_ShiftStr( SYS_DLLNAME_CGAME, -SYS_DLLNAME_CGAME_SHIFT ), &nChkSum1 ) == 1 );
		if ( bGood ) {
			bGood = ( FS_FileIsInPAK( FS_ShiftStr( SYS_DLLNAME_UI, -SYS_DLLNAME_UI_SHIFT ), &nChkSum2 ) == 1 );
		}

		cl->numPaks = nClientPaks = Cmd_Argc();

		// start at arg 2 ( skip serverId cl_paks )
		nCurArg = 1;

		pArg = Cmd_Argv( nCurArg++ );

		if ( !pArg ) {
			bGood = qfalse;
		} else
		{
			// show_bug.cgi?id=475
			// we may get incoming cp sequences from a previous checksumFeed, which we need to ignore
			// since serverId is a frame count, it always goes up
			if ( atoi( pArg ) < sv.checksumFeedServerId ) {
				Com_DPrintf( "ignoring outdated cp command from client %s\n", cl->name );
				return;
			}
		}

		// we basically use this while loop to avoid using 'goto' :)
		while ( bGood ) {

			// must be at least 6: "cl_paks cgame ui @ firstref ... numChecksums"
			// numChecksums is encoded
			if ( nClientPaks < 6 ) {
				bGood = qfalse;
				break;
			}
			// verify first to be the cgame checksum
			pArg = Cmd_Argv( nCurArg++ );
			if ( !pArg || *pArg == '@' || atoi( pArg ) != nChkSum1 ) {
				bGood = qfalse;
				break;
			}
			// verify the second to be the ui checksum
			pArg = Cmd_Argv( nCurArg++ );
			if ( !pArg || *pArg == '@' || atoi( pArg ) != nChkSum2 ) {
				bGood = qfalse;
				break;
			}
			// should be sitting at the delimeter now
			pArg = Cmd_Argv( nCurArg++ );
			if ( *pArg != '@' ) {
				bGood = qfalse;
				break;
			}
			// store checksums since tokenization is not re-entrant
			for ( i = 0; nCurArg < nClientPaks; i++ ) {
				cl->pakChecksums[i] = atoi( Cmd_Argv( nCurArg++ ) );
			}

			// store number to compare against (minus one cause the last is the number of checksums)
			nClientPaks = i - 1;

			// make sure none of the client check sums are the same
			// so the client can't send 5 the same checksums
			for ( i = 0; i < nClientPaks; i++ ) {
				for ( j = 0; j < nClientPaks; j++ ) {
					if ( i == j ) {
						continue;
					}
					if ( cl->pakChecksums[i] == cl->pakChecksums[j] ) {
						bGood = qfalse;
						break;
					}
				}
				if ( bGood == qfalse ) {
					break;
				}
			}
			if ( bGood == qfalse ) {
				break;
			}

			// get the pure checksums of the pk3 files loaded by the server
			pPaks = FS_LoadedPakPureChecksums();
			Cmd_TokenizeString( pPaks );
			nServerPaks = Cmd_Argc();
			if ( nServerPaks > 1024 ) {
				nServerPaks = 1024;
			}

			for ( i = 0; i < nServerPaks; i++ ) {
				nServerChkSum[i] = atoi( Cmd_Argv( i ) );
			}

			// check if the client has provided any pure checksums of pk3 files not loaded by the server
			for ( i = 0; i < nClientPaks; i++ ) {
				for ( j = 0; j < nServerPaks; j++ ) {
					if ( cl->pakChecksums[i] == nServerChkSum[j] ) {
						break;
					}
				}
				if ( j >= nServerPaks ) {
					bGood = qfalse;
					break;
				}
			}
			if ( bGood == qfalse ) {
				break;
			}

			// check if the number of checksums was correct
			nChkSum1 = sv.checksumFeed;
			for ( i = 0; i < nClientPaks; i++ ) {
				nChkSum1 ^= cl->pakChecksums[i];
			}
			nChkSum1 ^= nClientPaks;
			if ( nChkSum1 != cl->pakChecksums[nClientPaks] ) {
				bGood = qfalse;
				break;
			}

			// break out
			break;
		}

		cl->gotCP = qtrue;

		if ( bGood ) {
			cl->pureAuthentic = 1;
		} else if ( sv_allowUnpureClients->integer ) {
			char *message = va( "Unpure client detected: %s^7 has invalid .PK3 files referenced!", cl->name );
			SV_SendServerCommand( NULL, "cpm \"%s\n\"", message );
			Com_Printf( "%s\n", message );
			cl->pureAuthentic = 1;
		} else {
			cl->pureAuthentic = 0;
			cl->nextSnapshotTime = -1;
			cl->state = CS_ACTIVE;
			SV_SendClientSnapshot( cl );
			SV_DropClient( cl, "Unpure client detected. Invalid .PK3 files referenced!" );
		}
	}
}

/*
=================
SV_ResetPureClient_f
=================
*/
static void SV_ResetPureClient_f( client_t *cl ) {
	cl->pureAuthentic = 0;
	cl->gotCP = qfalse;
}

/*
=================
SV_UserinfoChanged

Pull specific info from a newly changed userinfo string
into a more C friendly form.
=================
*/
void SV_UserinfoChanged( client_t *cl ) {
	char    *val;
	int i;

	// name for C code
	Q_strncpyz( cl->name, Info_ValueForKey( cl->userinfo, "name" ), sizeof( cl->name ) );

	// rate command

	// if the client is on the same subnet as the server and we aren't running an
	// internet public server, assume they don't need a rate choke
	if ( Sys_IsLANAddress( cl->netchan.remoteAddress ) && com_dedicated->integer != 2 && sv_lanForceRate->integer == 1 ) {
		cl->rate = 99999;   // lans should not rate limit
	} else {
		val = Info_ValueForKey( cl->userinfo, "rate" );
		if ( strlen( val ) ) {
			i = atoi( val );
			cl->rate = i;
			if ( cl->rate < 1000 ) {
				cl->rate = 1000;
			} else if ( cl->rate > 90000 ) {
				cl->rate = 90000;
			}
		} else {
			cl->rate = 5000;
		}
	}
	val = Info_ValueForKey( cl->userinfo, "handicap" );
	if ( strlen( val ) ) {
		i = atoi( val );
		if ( i <= -100 || i > 100 || strlen( val ) > 4 ) {
			Info_SetValueForKey( cl->userinfo, "handicap", "0" );
		}
	}

	// snaps command
	val = Info_ValueForKey( cl->userinfo, "snaps" );
	if ( strlen( val ) ) {
		i = atoi( val );
		if ( i < 1 ) {
			i = 1;
		} else if ( i > 30 ) {
			i = 30;
		}
		cl->snapshotMsec = 1000 / i;
	} else {
		cl->snapshotMsec = 50;
	}

	// TTimo
	// maintain the IP information
	// this is set in SV_DirectConnect (directly on the server, not transmitted), may be lost when client updates it's userinfo
	// the banning code relies on this being consistently present
	// zinx - modified to always keep this consistent, instead of only
	// when "ip" is 0-length, so users can't supply their own IP
	//Com_DPrintf("Maintain IP in userinfo for '%s'\n", cl->name);
	if ( !NET_IsLocalAddress( cl->netchan.remoteAddress ) ) {
		Info_SetValueForKey( cl->userinfo, "ip", NET_AdrToString( cl->netchan.remoteAddress ) );
	} else {
		// force the "ip" info key to "localhost" for local clients
		Info_SetValueForKey( cl->userinfo, "ip", "localhost" );
	}

	// TTimo
	// download prefs of the client
	val = Info_ValueForKey( cl->userinfo, "cl_wwwDownload" );
	cl->bDlOK = qfalse;
	if ( strlen( val ) ) {
		i = atoi( val );
		if ( i != 0 ) {
			cl->bDlOK = qtrue;
		}
	}

#ifdef WIN32
	// disable auto sleep as long as someone is on the server
	SetThreadExecutionState( ES_SYSTEM_REQUIRED | ES_CONTINUOUS );
#endif
}


void SV_NumberName( client_t *cl ) {
	char *originalname;
	char newname[MAX_NAME_LENGTH];
	static char prefix[MAX_NAME_LENGTH / 2] = "";
	static char prefix2[MAX_NAME_LENGTH / 2] = "";

	if ( sv_numberedNamesDecoration->modified ) {
		char *p;

		Q_strncpyz( prefix, sv_numberedNamesDecoration->string, sizeof( prefix ) );
		p = strrchr( prefix, ';' );
		if ( p ) {
			Q_strncpyz( prefix2, p + 1, sizeof( prefix2 ) );
		} else {
			prefix2[0] = '\0';
		}
		p = strchr( prefix, ';' );
		if ( p ) {
			*p = '\0';
		}
		sv_numberedNamesDecoration->modified = qfalse;
	}

	originalname = Info_ValueForKey( cl->userinfo, "name" );
	Info_SetValueForKey( cl->userinfo, "originalname", originalname );

	if ( sv_numberedNames->integer ) {
		if ( sv_numberedNames->integer == 2 ) {
			Com_sprintf( newname, sizeof( newname ), "%s%2d %s%s", prefix, cl - svs.clients, prefix2, originalname );
		} else if ( sv_numberedNames->integer == 3 ) {
			Com_sprintf( newname, sizeof( newname ), "%s%02d %s%s", prefix, cl - svs.clients, prefix2, originalname );
		} else if ( sv_numberedNames->integer == 4 ) {
			int clientNum = cl - svs.clients;

			if ( clientNum < 10 ) {
				Com_sprintf( newname, sizeof( newname ), "%s%d  %s%s", prefix, clientNum, prefix2, originalname );
			} else {
				Com_sprintf( newname, sizeof( newname ), "%s%d %s%s", prefix, clientNum, prefix2, originalname );
			}
		} else {
			Com_sprintf( newname, sizeof( newname ), "%s%d %s%s", prefix, cl - svs.clients, prefix2, originalname );
		}
		Info_SetValueForKey( cl->userinfo, "name", newname );
	}
}


/*
==================
SV_UpdateUserinfo_f
==================
*/
static void SV_UpdateUserinfo_f( client_t *cl ) {
	char *cl_guid = Info_ValueForKey( cl->userinfo, "cl_guid" );

	Q_strncpyz( cl->userinfo, Cmd_Argv( 1 ), sizeof( cl->userinfo ) );

	if ( *cl_guid ) {
		Info_SetValueForKey( cl->userinfo, "cl_guid", cl_guid );
	}

	SV_NumberName( cl );

	SV_UserinfoChanged( cl );
	// call prog code to allow overrides
	VM_Call( gvm, GAME_CLIENT_USERINFO_CHANGED, cl - svs.clients );
}

typedef struct {
	char        *name;
	void ( *func )( client_t *cl );
	qboolean allowedpostmapchange;
} ucmd_t;

static ucmd_t ucmds[] = {
	{"userinfo", SV_UpdateUserinfo_f,    qfalse },
	{"disconnect",   SV_Disconnect_f,        qtrue },
	{"cp",           SV_VerifyPaks_f,        qfalse },
	{"vdr",          SV_ResetPureClient_f,   qfalse },
	{"download", SV_BeginDownload_f,     qfalse },
	{"nextdl",       SV_NextDownload_f,      qfalse },
	{"stopdl",       SV_StopDownload_f,      qfalse },
	{"donedl",       SV_DoneDownload_f,      qfalse },
	{"wwwdl",        SV_WWWDownload_f,       qfalse },
	{"listmaps",	SV_ListMaps_f,		qfalse},
	{"maplist",		SV_MapList_f,		qfalse},
	{"findmap",		SV_FindMap_f,		qfalse},
	{"mapinfo",		SV_MapInfo_f,		qfalse},
	{"minfo",		SV_MapInfo_f,		qfalse},
	{"cv",			SV_CV_f,		    qfalse},
	{"feedback",    SV_UserFeedback_f,  qtrue},
	{NULL, NULL}
};

void SV_Save_f( client_t *cl ) {
	char *P = Cvar_VariableString( "P" );
	playerState_t *ps = SV_GameClientNum( cl - svs.clients );
	int team = 0;

	if ( ps->stats[STAT_HEALTH] <= 0 ) {
		SV_SendServerCommand( cl, "cp \"Can't save while dead.\n\"" );
		return;
	}

	if ( P[cl - svs.clients] == '1' ) {
		team = 1;
	} else if ( P[cl - svs.clients] == '2' ) {
		team = 2;
	}
	if ( cl->savedPositions[team] ) {
		Z_Free( cl->savedPositions[team] );
	}
	cl->savedPositions[team] = Z_Malloc( sizeof ( playerState_t ) );
	*cl->savedPositions[team] = *ps;
	SV_SendServerCommand( cl, "cp \"Saved\n\"" );
	return;
}

void SV_Load_f( client_t *cl ) {
	char *P = Cvar_VariableString( "P" );
	playerState_t *ps = SV_GameClientNum( cl - svs.clients );
	int team = 0;
	int i;

	if ( P[cl - svs.clients] == '1' ) {
		team = 1;
	} else if ( P[cl - svs.clients] == '2' ) {
		team = 2;
	}
	if ( cl->savedPositions[team] && ps->stats[STAT_HEALTH] > 0 ) {
		*ps = *cl->savedPositions[team];
		for ( i = 0; i < 3; i++ ) {
			ps->delta_angles[i] = ANGLE2SHORT( ps->viewangles[i] ) - cl->lastUsercmd.angles[i];
		}
		SV_SendServerCommand( cl, "cp \"Loaded\n\"" );
	} /*else {
		SV_SendServerCommand( cl, "cp \"Use save first\n\"" );
	}*/
	return;
}

/*
==================
SV_ExecuteClientCommand

Also called by bot code
==================
*/
void SV_ExecuteClientCommand( client_t *cl, const char *s, qboolean clientOK, qboolean premaprestart ) {
	ucmd_t  *u;
	qboolean bProcessed = qfalse;
	char *lowerArgv0;

	Cmd_TokenizeString( s );
	lowerArgv0 = Q_strlwr( va( "%s", Cmd_Argv( 0 ) ) );

	// see if it is a server level command
	for ( u = ucmds ; u->name ; u++ ) {
		if ( !strcmp( lowerArgv0, u->name ) ) {
			if ( premaprestart && !u->allowedpostmapchange ) {
				continue;
			}

			u->func( cl );
			bProcessed = qtrue;
			break;
		}
	}

	if ( sv_save->integer ) {
		if ( !strcmp( lowerArgv0, "save" ) ) {
			SV_Save_f( cl );
			return;
		} else if ( !strcmp( lowerArgv0, "load" ) ) {
			SV_Load_f( cl );
			return;
		}
	}

	if ( clientOK ) {
		if ( sv_processVoiceChats->integer ) {
			if ( !strcmp( lowerArgv0, "vsay") ) {
				char buf[MAX_INFO_STRING];

				SV_GetConfigstring( CS_PLAYERS + ( cl - svs.clients ), buf, sizeof( buf ) );
				if ( atoi( Info_ValueForKey( buf, "mu" ) ) ) {
					return;
				}
				if ( cl->voiceChatTime < svs.time - 30000 ) {
					cl->voiceChatTime = svs.time - 30000;
				}
				if ( cl->voiceChatTime + 30000 / sv_processVoiceChats->integer > svs.time ) {
					SV_SendServerCommand( cl, "cpm \"^1Spam Protection^7: VoiceChat ignored\n\"" );
					return;
				}
				SV_SendServerCommand( NULL, "vchat 0 %d 50 %s", cl - svs.clients, Cmd_Argv( 1 ) );
				Com_Printf( "voice: %s %s\n", cl->name, Cmd_Argv( 1 ) );
				cl->voiceChatTime += 30000 / sv_processVoiceChats->integer;
				return;
			}
		}

		// pass unknown strings to the game
		if ( !u->name && sv.state == SS_GAME ) {
			VM_Call( gvm, GAME_CLIENT_COMMAND, cl - svs.clients );
		}

		if ( *sv_chatConnectedServers->string ) {
			if ( !strcmp( lowerArgv0, "say" ) || !strcmp( lowerArgv0, "enc_say" ) ) {
				char buf[MAX_INFO_STRING];

				SV_GetConfigstring( CS_PLAYERS + ( cl - svs.clients ), buf, sizeof( buf ) );
				if ( !atoi( Info_ValueForKey( buf, "mu" ) ) ) {
					SV_SendToChatConnectedServers( va( "rsay %s:^7%s^7: ^2%s", *sv_chatHostname->string ? sv_chatHostname->string : sv_hostname->string, cl->name, Cmd_Args() ) );
				}
			}
		}
		if ( sv_chatCommands->integer ) {
			if ( !strcmp( lowerArgv0, "say" ) || !strcmp( lowerArgv0, "enc_say" ) ) {
				char *cmd;
				//char cmdString[BIG_INFO_STRING];
				const char *checkConsole = "chat \"^zCheck console for more information.\"";

				//Q_strncpyz( cmdString, Cmd_Cmd(), sizeof( cmdString ) );
				Cmd_TokenizeString( Cmd_Args() );
				cmd = Cmd_Argv( 0 );
				if ( cmd[0] == '\\' || cmd[0] == '/' ) {
					if ( !Q_stricmp( cmd + 1, "MINFO" ) ) {
						SV_SendServerCommand( cl, checkConsole );
						SV_MapInfo_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "LISTMAPS" ) ) {
						SV_SendServerCommand( cl, checkConsole );
						SV_ListMaps_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "FINDMAP" ) ) {
						SV_SendServerCommand( cl, checkConsole );
						SV_FindMap_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "FEEDBACK" ) ) {
						SV_UserFeedback_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "SAVE" ) ) {
						SV_Save_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "LOAD" ) ) {
						SV_Load_f( cl );
					} else if ( !Q_stricmp( cmd + 1, "CV" ) ) {
						Cmd_TokenizeString( va( "callvote %s", Cmd_Args() ) );
						if ( sv.state == SS_GAME ) {
							VM_Call( gvm, GAME_CLIENT_COMMAND, cl - svs.clients );
						}
					}
			} else if ( cmd[0] == '!' ) { 
					cmd++;
					if ( !Q_stricmp( cmd, "MINFO" ) ) {
						char buf[MAX_INFO_STRING];

						SV_GetConfigstring( CS_PLAYERS + ( cl - svs.clients ), buf, sizeof( buf ) );
						if ( !atoi( Info_ValueForKey( buf, "mu" ) ) ) {
							SV_MapInfo_f( cl );
						}
					} else if ( !Q_stricmp( cmd, "FEEDBACK" ) ) {
						SV_UserFeedback_f( cl );
					} else if ( !Q_stricmp( cmd, "CV" ) ) {
						Cmd_TokenizeString( va( "callvote %s", Cmd_Args() ) );
						if ( sv.state == SS_GAME ) {
							VM_Call( gvm, GAME_CLIENT_COMMAND, cl - svs.clients );
						}
					}
				}
			}
		}

	} else if ( !bProcessed )     {
		Com_DPrintf( "client text ignored for %s: %s\n", cl->name, Cmd_Argv( 0 ) );
	}
}

/*
===============
SV_ClientCommand
===============
*/
static qboolean SV_ClientCommand( client_t *cl, msg_t *msg, qboolean premaprestart ) {
	int seq;
	const char  *s;
	qboolean clientOk = qtrue;
	qboolean floodprotect = qtrue;

	seq = MSG_ReadLong( msg );
	s = MSG_ReadString( msg );

	// see if we have already executed it
	if ( cl->lastClientCommand >= seq ) {
		return qtrue;
	}

	if ( sv_floodThreshold->integer > 0 ) {
		if ( svs.time - cl->floodTime > 9500 ) {
			cl->floodTime = svs.time - 9500;
		}
		if ( cl->floodTime >= svs.time ) {
			goto last_client_command;
		}

		if ( !Q_strncmp( "team", s, 4 ) || !Q_strncmp( "setspawnpt", s, 10 ) || !Q_strncmp( "score", s, 5 ) || !Q_stricmp( "forcetapout", s ) 
			|| !Q_strncmp( "imvotetally", s, 11 ) || !Q_strncmp( "obj", s, 3 ) )
			cl->floodTime += 2500 / sv_floodThreshold->integer;
		else
			cl->floodTime += 10000 / sv_floodThreshold->integer;
	}

	if ( sv_showClientCmds->integer ) {
		Cmd_TokenizeString( s );
		if ( Q_stricmp( Cmd_Argv( 0 ), "nextdl" ) == 0 && atoi( Cmd_Argv( 1 ) ) % 10 != 0 ) {
		} else {
			Com_Printf( "clientCommand: %s : %i : %s\n", cl->name, seq, s );
		}
	} else {
		Com_DPrintf( "clientCommand: %s : %i : %s\n", cl->name, seq, s );
	}

	if ( !Q_stricmpn( "TEAM", s, 4 ) || Cvar_VariableIntegerValue( "gamestate" ) == GS_INTERMISSION ) {
		cl->lastActivityTime = svs.time;
	}

	// drop the connection if we have somehow lost commands
	if ( seq > cl->lastClientCommand + 1 ) {
		Com_Printf( "Client %s lost %i clientCommands\n", cl->name, seq - cl->lastClientCommand + 1 );
		SV_DropClient( cl, "Lost reliable commands" );
		return qfalse;
	}

	if ( sv_floodProtect->integer ) {

		// Gordon: AHA! Need to steal this for some other stuff BOOKMARK
		// NERVE - SMF - some server game-only commands we cannot have flood protect
		if ( !Q_strncmp( "team", s, 4 ) || !Q_strncmp( "setspawnpt", s, 10 ) || !Q_strncmp( "score", s, 5 ) || !Q_stricmp( "forcetapout", s ) ) {
	//		Com_DPrintf( "Skipping flood protection for: %s\n", s );
			floodprotect = qfalse;
		}

		// malicious users may try using too many string commands
		// to lag other players.  If we decide that we want to stall
		// the command, we will stop processing the rest of the packet,
		// including the usercmd.  This causes flooders to lag themselves
		// but not other people
		// We don't do this when the client hasn't been active yet since its
		// normal to spam a lot of commands when downloading
		if ( !com_cl_running->integer &&
			 cl->state >= CS_ACTIVE &&      // (SA) this was commented out in Wolf.  Did we do that?
	//		 sv_floodProtect->integer &&
			 svs.time < cl->nextReliableTime &&
			 floodprotect ) {
			// ignore any other text messages from this client but let them keep playing
			// TTimo - moved the ignored verbose to the actual processing in SV_ExecuteClientCommand, only printing if the core doesn't intercept
			clientOk = qfalse;
		}

		// don't allow another command for 800 msec
		if ( floodprotect &&
			 svs.time >= cl->nextReliableTime ) {
			cl->nextReliableTime = svs.time + 800;
		}
	}

	SV_ExecuteClientCommand( cl, s, clientOk, premaprestart );

last_client_command:
	cl->lastClientCommand = seq;
	Com_sprintf( cl->lastClientCommandString, sizeof( cl->lastClientCommandString ), "%s", s );

	return qtrue;       // continue procesing
}


//==================================================================================


/*
==================
SV_ClientThink

Also called by bot code
==================
*/
void SV_ClientThink( client_t *cl, usercmd_t *cmd ) {
	if ( cmd->buttons != cl->lastUsercmd.buttons || cmd->wbuttons != cl->lastUsercmd.wbuttons 
		|| cmd->forwardmove != cl->lastUsercmd.forwardmove || cmd->rightmove != cl->lastUsercmd.rightmove || cmd->upmove != cl->lastUsercmd.upmove ) {
		cl->lastActivityTime = cmd->serverTime;
	}

	cl->lastUsercmd = *cmd;

	if ( cl->state != CS_ACTIVE ) {
		return;     // may have been kicked during the last usercmd
	}

	if ( sv_disabledWeapons1->integer ) {
		playerState_t *ps = SV_GameClientNum( cl - svs.clients );
		int weapons[2];

		weapons[0] = sv_disabledWeapons1->integer;
		weapons[1] = sv_disabledWeapons2->integer;
		if ( COM_BitCheck( weapons, cmd->weapon ) ) {
			COM_BitClear( ps->weapons, cmd->weapon );
			ps->weaponstate = 1;
			//cmd->buttons &= ~BUTTON_ATTACK;
			//cmd->wbuttons &= ~WBUTTON_ATTACK2;
		}
	}

	VM_Call( gvm, GAME_CLIENT_THINK, cl - svs.clients );
	if ( cmd->buttons ) {
		int i;

		for ( i = 0 ; i < 8 ; i++ ) {
			if ( cmd->buttons & 1 << i ) {
				cl->lastUsercmdTimes.buttons[i] = cmd->serverTime;
			}
		}
	}
	if ( cmd->wbuttons ) {
		int i;

		for ( i = 0 ; i < 8 ; i++ ) {
			if ( cmd->wbuttons & 1 << i ) {
				cl->lastUsercmdTimes.wbuttons[i] = cmd->serverTime;
			}
		}
	}
	if ( cmd->forwardmove ) {
		cl->lastUsercmdTimes.forwardmove = cmd->serverTime;
	}
	if ( cmd->rightmove ) {
		cl->lastUsercmdTimes.rightmove = cmd->serverTime;
	}
	if ( cmd->upmove ) {
		cl->lastUsercmdTimes.upmove = cmd->serverTime;
	}
}

/*
==================
SV_UserMove

The message usually contains all the movement commands
that were in the last three packets, so that the information
in dropped packets can be recovered.

On very fast clients, there may be multiple usercmd packed into
each of the backup packets.
==================
*/
static void SV_UserMove( client_t *cl, msg_t *msg, qboolean delta ) {
	int i, key;
	int cmdCount;
	usercmd_t nullcmd;
	usercmd_t cmds[MAX_PACKET_USERCMDS];
	usercmd_t   *cmd, *oldcmd;

	if ( delta ) {
		cl->deltaMessage = cl->messageAcknowledge;
	} else {
		cl->deltaMessage = -1;
	}

	cmdCount = MSG_ReadByte( msg );

	if ( cmdCount < 1 ) {
		Com_Printf( "cmdCount < 1\n" );
		return;
	}

	if ( cmdCount > MAX_PACKET_USERCMDS ) {
		Com_Printf( "cmdCount > MAX_PACKET_USERCMDS\n" );
		return;
	}

	// use the checksum feed in the key
	key = sv.checksumFeed;
	// also use the message acknowledge
	key ^= cl->messageAcknowledge;
	// also use the last acknowledged server command in the key
	key ^= Com_HashKey( cl->reliableCommands[ cl->reliableAcknowledge & ( MAX_RELIABLE_COMMANDS - 1 ) ], 32 );

	memset( &nullcmd, 0, sizeof( nullcmd ) );
	oldcmd = &nullcmd;
	for ( i = 0 ; i < cmdCount ; i++ ) {
		cmd = &cmds[i];
		MSG_ReadDeltaUsercmdKey( msg, key, oldcmd, cmd );
//		MSG_ReadDeltaUsercmd( msg, oldcmd, cmd );
		oldcmd = cmd;
	}

	// save time for ping calculation
	cl->frames[ cl->messageAcknowledge & PACKET_MASK ].messageAcked = svs.time;

	// TTimo
	// catch the no-cp-yet situation before SV_ClientEnterWorld
	// if CS_ACTIVE, then it's time to trigger a new gamestate emission
	// if not, then we are getting remaining parasite usermove commands, which we should ignore
	if ( sv_pure->integer != 0 && cl->pureAuthentic == 0 && !cl->gotCP ) {
		if ( cl->state == CS_ACTIVE ) {
			// we didn't get a cp yet, don't assume anything and just send the gamestate all over again
			Com_DPrintf( "%s: didn't get cp command, resending gamestate\n", cl->name );
			SV_SendClientGameState( cl );
		}
		return;
	}

	// if this is the first usercmd we have received
	// this gamestate, put the client into the world
	if ( cl->state == CS_PRIMED ) {
		SV_ClientEnterWorld( cl, &cmds[0] );
		// the moves can be processed normaly
	}

	// a bad cp command was sent, drop the client
	if ( sv_pure->integer != 0 && cl->pureAuthentic == 0 ) {
		SV_DropClient( cl, "Cannot validate pure client!" );
		return;
	}

	if ( cl->state != CS_ACTIVE ) {
		cl->deltaMessage = -1;
		return;
	}

	// usually, the first couple commands will be duplicates
	// of ones we have previously received, but the servertimes
	// in the commands will cause them to be immediately discarded
	for ( i =  0 ; i < cmdCount ; i++ ) {
		// if this is a cmd from before a map_restart ignore it
		if ( cmds[i].serverTime > cmds[cmdCount - 1].serverTime ) {
			continue;
		}
		// extremely lagged or cmd from before a map_restart
		//if ( cmds[i].serverTime > svs.time + 3000 ) {
		//	continue;
		//}
		if ( !SV_GameIsSinglePlayer() ) { // We need to allow this in single player, where loadgame's can cause the player to freeze after reloading if we do this check
			// don't execute if this is an old cmd which is already executed
			// these old cmds are included when cl_packetdup > 0
			if ( cmds[i].serverTime <= cl->lastUsercmd.serverTime ) {   // Q3_MISSIONPACK
//			if ( cmds[i].serverTime > cmds[cmdCount-1].serverTime ) {
				continue;   // from just before a map_restart
			}
		}
		SV_ClientThink( cl, &cmds[ i ] );
	}
}


/*
=====================
SV_ParseBinaryMessage
=====================
*/
static void SV_ParseBinaryMessage( client_t *cl, msg_t *msg ) {
	int size;

	MSG_BeginReadingUncompressed( msg );

	size = msg->cursize - msg->readcount;
	if ( size <= 0 || size > MAX_BINARY_MESSAGE ) {
		return;
	}

	SV_GameBinaryMessageReceived( cl - svs.clients, &msg->data[msg->readcount], size, cl->lastUsercmd.serverTime );
}

/*
===========================================================================

USER CMD EXECUTION

===========================================================================
*/

/*
===================
SV_ExecuteClientMessage

Parse a client packet
===================
*/
void SV_ExecuteClientMessage( client_t *cl, msg_t *msg ) {
	int c;
	int serverId;

	MSG_Bitstream( msg );

	serverId = MSG_ReadLong( msg );
	cl->messageAcknowledge = MSG_ReadLong( msg );

	if ( cl->messageAcknowledge < 0 ) {
		// usually only hackers create messages like this
		// it is more annoying for them to let them hanging
#ifndef NDEBUG
		SV_DropClient( cl, "DEBUG: illegible client message" );
#endif
		return;
	}

	cl->reliableAcknowledge = MSG_ReadLong( msg );

	// NOTE: when the client message is fux0red the acknowledgement numbers
	// can be out of range, this could cause the server to send thousands of server
	// commands which the server thinks are not yet acknowledged in SV_UpdateServerCommandsToClient
	if ( cl->reliableAcknowledge < cl->reliableSequence - MAX_RELIABLE_COMMANDS ) {
		// usually only hackers create messages like this
		// it is more annoying for them to let them hanging
#ifndef NDEBUG
		SV_DropClient( cl, "DEBUG: illegible client message" );
#endif
		cl->reliableAcknowledge = cl->reliableSequence;
		return;
	}
	// if this is a usercmd from a previous gamestate,
	// ignore it or retransmit the current gamestate
	//
	// if the client was downloading, let it stay at whatever serverId and
	// gamestate it was at.  This allows it to keep downloading even when
	// the gamestate changes.  After the download is finished, we'll
	// notice and send it a new game state
	//
	// show_bug.cgi?id=536
	// don't drop as long as previous command was a nextdl, after a dl is done, downloadName is set back to ""
	// but we still need to read the next message to move to next download or send gamestate
	// I don't like this hack though, it must have been working fine at some point, suspecting the fix is somewhere else
	if ( serverId != sv.serverId && !*cl->downloadName && !strstr( cl->lastClientCommandString, "nextdl" ) ) {
		if ( serverId >= sv.restartedServerId && serverId < sv.serverId ) { // TTimo - use a comparison here to catch multiple map_restart
			// they just haven't caught the map_restart yet
			Com_DPrintf( "%s : ignoring pre map_restart / outdated client message\n", cl->name );
			return;
		}
		// if we can tell that the client has dropped the last
		// gamestate we sent them, resend it
		if ( cl->messageAcknowledge > cl->gamestateMessageNum ) {
			Com_DPrintf( "%s : dropped gamestate, resending\n", cl->name );
			SV_SendClientGameState( cl );
		}

		// read optional clientCommand strings
		do {
			c = MSG_ReadByte( msg );
			if ( c == clc_EOF ) {
				break;
			}
			if ( c != clc_clientCommand ) {
				break;
			}
			if ( !SV_ClientCommand( cl, msg, qtrue ) ) {
				return; // we couldn't execute it because of the flood protection
			}
			if ( cl->state == CS_ZOMBIE ) {
				return; // disconnect command
			}
		} while ( 1 );

		return;
	}

	// read optional clientCommand strings
	do {
		c = MSG_ReadByte( msg );
		if ( c == clc_EOF ) {
			break;
		}
		if ( c != clc_clientCommand ) {
			break;
		}
		if ( !SV_ClientCommand( cl, msg, qfalse ) ) {
			return; // we couldn't execute it because of the flood protection
		}
		if ( cl->state == CS_ZOMBIE ) {
			return; // disconnect command
		}
	} while ( 1 );

	// read the usercmd_t
	if ( c == clc_move ) {
		SV_UserMove( cl, msg, qtrue );
		c = MSG_ReadByte( msg );
	} else if ( c == clc_moveNoDelta ) {
		SV_UserMove( cl, msg, qfalse );
		c = MSG_ReadByte( msg );
	}

	if ( c != clc_EOF ) {
		Com_Printf( "WARNING: bad command byte for client %i\n", cl - svs.clients );
	}

	SV_ParseBinaryMessage( cl, msg );

//	if ( msg->readcount != msg->cursize ) {
//		Com_Printf( "WARNING: Junk at end of packet for client %i\n", cl - svs.clients );
//	}
}
