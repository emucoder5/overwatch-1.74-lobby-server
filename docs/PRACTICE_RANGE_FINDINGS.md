# Practice Range: where it actually stands, and the next move

Read of the whole tree (`ow174/`, `jam/`, `matches/`, `experiments/`, `tools/`, `relay/`),
the captures in `logs/matches/`, `logs/ow174.log`, `relay/log/wfd.log`, and the Ghidra dump.

## The headline: `docs/STATE.md` is out of date. The handoff is solved.

STATE.md says the handoff (20600) is ignored and the game "opens no new socket and sends
nothing." That is no longer true. The `practice_plain_host` plan worked. `logs/ow174.log`
and three capture folders show, three separate runs:

- handoff sent with **first field = false** (payload *not* encrypted) and the game-server
  address written **as ASCII text in the 64-byte field at +0x2E**, and
- the game then opens a UDP socket and sends **39–40 connect packets** to `127.0.0.1:3730`.

So the "which 20600 encoding makes the game connect" question is answered. `relay/log/wfd.log`
confirms it at the syscall level: `NET sendto UDP -> 127.0.0.1:3730 socket=5996 bytes=34`.

## The real blocker now: nothing answers the game on the game-server socket.

Two facts, together, explain the timeout:

1. **The game's connect packet is understood.** Every one of the 34 bytes is accounted for
   (byte-aligned from the `wfd.log` TRACE):

   | offset | size | meaning |
   |---|---|---|
   | 0 | 12 | per-packet token — different every packet (the "signed" field) |
   | 12 | 4 | `F0 00 00 10` = LE `0xF0000010`, constant command/channel tag |
   | 16 | 4 | sequence u32 LE: `0,1,2,…` one per packet |
   | 20 | 12 | zero |
   | 32 | 2 | `01 AD`, constant footer |

   The client sends this ~4×/second, incrementing `seq`, with a fresh token each time, and
   **stops after ~39 packets** — a classic connect-request retransmit loop that never gets a
   reply.

2. **The thing it connects to never replies.** `matches/instance.py` is a *passive UDP
   recorder*: it `recvfrom`s, logs, and hard-codes `protocol_ready = False`. It sends nothing
   back, ever. So the client waits and times out. `ENTERING PRACTICE RANGE` on screen is just
   the client waiting on this socket, exactly as the old control test noted.

### Clearing up two things that look like leads but aren't

- **JAM / PANAMA is not this protocol.** `jam/handshake.py` (HELLO PRO CLIENT/SERVER, nonce +
  key proof, 292-byte state blob) over **TCP** is the **lobby** protocol, and it already works
  — that's how login and the menu run (`lobby/server.py` accepts TCP on 3724 and runs
  `server_handshake`; `tools/fake_client.py` plays the client side and passes). The connect
  frame above is **UDP** and does **not** begin with `HELLO PRO CLIENT`. Don't try to bolt JAM
  onto the game socket; it's a different, realtime protocol.

- **The Ghidra dump you have is the *send* path, not the *receive* path.** All 16 stack walks
  in `ghidra_dump.txt` were captured at the `sendto` site, so they trace how the client
  *builds and signs* the connect packet. To know what to *reply*, we need the function that
  handles bytes *received* on that UDP socket — which is not in this dump. The two big
  networking functions that would matter most (`FUN_7ff6328aed70` @ RVA `0x59ED70`, the engine
  at stack-walk 6; and its callers at `0x7CF230`, `0x1832F00`) **failed to decompile**
  ("Flow exceeded maximum allowable instructions"). That's the wall STATE.md hit.

## The next move (two tracks)

### Track A — make the server answer, and watch the client (do this first; cheap, offline)

Before reverse-engineering the exact reply, find out the one thing that decides everything:
**does the client process *any* reply on this socket?** Right now that has never been tested,
because nothing has ever replied.

`responder.py` (included) is a drop-in replacement for `instance.py` that replies to each
connect frame and flags when the client's outbound stream changes shape versus the silent
baseline (new command tag, nonzero body, seq reset, a second source port — any of these means
it reacted). It ships four guessed reply templates (`echo`, `echo_seq0`, `accept_cmd`,
`challenge`) and takes a `--reply-plan` JSON for your own.

Wire it in by changing one line in `matches/runtime.py::_instance_command`:
`"ow174.matches.instance"` → `"ow174.matches.responder"`, then run the practice flow.
Read `logs/matches/<id>/state.json` (`client_reacted`, `shapes_seen`) and `replies.jsonl`.

- If `client_reacted` flips **true** for some template → the socket's receive path is live and
  you've found the reply family to refine. Huge.
- If it stays **false** across every template even at packet 1 → the client isn't keying off
  this socket's replies yet (e.g. it's still waiting on a lobby-side message such as a 56200
  MATCH_STATE assignment before it will accept a game-server reply), which redirects the search
  to the lobby side. Either outcome is real information; today there is none.

### Track B — get the receive path out of the binary (needed for the correct reply)

The send path is fully mapped; you need its mirror. To get a clean decompile:

1. In `tools/ghidra/DumpOverwatch.java`, raise the decompiler limit for the failed functions:
   `DecompInterface` → `setOptions` with a larger `maxInstructions` (or `MaxInstructions`
   property), and dump `0x59ED70`, `0x7CF230`, `0x1832F00` specifically.
2. Find the **recvfrom** side: the game creates the UDP socket at `wfd.log` `socket=5996`.
   Add a `recvfrom`/`WSARecvFrom` hook to `relay/owwfd_relay.cpp` (it currently hooks only the
   TCP byte-stream and the `sendto` TRACE — grep shows no UDP recv hook), stack-walk it the
   same way, and those RVAs are the parser/validator for the reply. Decompile those.
3. The token is the key unknown: 12 bytes, fresh per packet. Whether it's an HMAC/hash over
   `(cmd, seq, secret)` or a rolling nonce decides what a valid *server* token must look like.
   The signing functions on the send stack (Track B step 1) define it; read them alongside the
   recv validator.

## One-line summary

Getting the client to *dial* the practice-range game server is done; what's left is speaking
its realtime UDP protocol back to it, and the fastest first step is to reply with guesses and
watch whether it reacts (`responder.py`), while pulling the receive-path decompile to learn
the real reply.
