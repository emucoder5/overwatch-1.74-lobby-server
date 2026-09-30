# Practice Range: where it actually stands, and the next move

## Update (2026-09-30, run `9eec49a9`): our replies are dropped BEFORE the tag check

With the breakpoints armed only after the game dialed 3730, the trace survived about 2 s (then the game
closed again, so its protection also checks while it runs) and caught 9 calls. They settle two things:

- **The two leaves were labelled the wrong way round.** `0x24D2770` computes the tag and writes it into
  the packet (seal). The logged call for seq 3 (key pointer, AAD = the header with seq 3, nonce =
  `4444444444444444` || 3) gives exactly the game's own packet-3 tag with the `+0xAE` key. `0x24D2500`
  is the same code ending in a compare (`call 0x24D3E90`, `sete al`): the verify. Both take
  `(ctx, aad, cbAad, data, cbData, nonce, cbNonce, tag, cbTag)` and return a bool in `al`.
- **The verify never ran.** DR0 was on `0x24D2500` on the same 153 threads while 9 `echo_ce` replies
  arrived (RECVDATA), and it never fired. The open wrapper `0x3FB2E0` goes straight to the verify with
  no checks of its own. So the game's receive handler (obfuscated) throws our replies away on something
  in the plain header or the datagram before any crypto. The key question is no longer "is the cipher
  right" but "what header does the receive handler accept".

Next: `PRACTICE_REPLIES.bat` option 5 (`experiments/replies/header_sweep.json`) sends 564 correctly
sealed headers, each varying one field: the command's top byte, its low byte, the 12-byte body (the
handoff's probe ids and u64s) and the footer. They go out in bursts on game packets 1-8, inside the ~2 s
the trace survives. Any header that gets past the check shows up as a `GCM verify PASS/FAIL` line with
its `aad=`.

## Update (2026-09-30, run `f7b869da`): the game's code cannot be patched; the trace uses hardware breakpoints

`echo_ce` + trace: the prologues of GcmEncrypt/GcmDecrypt matched at launch, but the inline hook failed
with `VirtualProtect failed 87` on both, so nothing was logged. The game image cannot be re-protected,
so no inline patch of game code will ever work. The replies were read again (37 x `RECVDATA ... got=34`),
and `client_reacted` stayed false. The trace now puts hardware breakpoints (DR0/DR1) on the two leaves
on every game thread, plus DR2 on each call's return address for the return value, using a vectored
exception handler. No game byte changes. Same switch (`PRACTICE_REPLIES.bat` option 4), and the same
`GCM decrypt AUTH-OK` / `AUTH-FAIL` lines in `wfd.log`. If the game's protection checks the debug
registers, it may exit or crash with the trace on; that result is worth reporting too.

It did: with breakpoints set at launch (15 threads within 1.3 s), the game closed about 2 s later, before
the menu, twice. The trace now waits until the game sends its first packet to the game server
(UDP 3730-3749), so nothing is armed while the game starts up.

## Update (2026-09-30): the "token" is an AES-256-GCM tag, and the key comes from the handoff

The responder run (`logs/matches/713ac6d1fd11486e932ac7ed03e46d59`) plus the new `recvfrom` hook settled
the question Track A asked: `relay/log/wfd.log` has `RECVDATA recvfrom UDP local=:63884 from
127.0.0.1:3730 got=34` for the replies, so **the game reads every reply on the game socket**. It ignored
them because they failed authentication:

- The 12 "token" bytes are the first 12 bytes of an **AES-256-GCM tag** over an empty plaintext, with
  AAD = the other 22 bytes and nonce = 8-byte prefix || seq (u32 LE). In that run the key and the
  prefix were **all zero**, and the handoff's two `u8[32]` fields (`+0x80+0xAE`, `+0x80+0xCE`) were
  zero too. All 39 captured packets verify (`py -m ow174.matches.gamecrypto logs\matches\<id>`).
- Of the old reply templates only `echo` carried a valid tag (the others could never pass), and an echo
  of the client's own connect command changed nothing.

Where this is in the client image (`logs/overwatch_image.zip`, base `0x7FF632310000`, RVAs):

| RVA | what |
|---|---|
| `0x24D2500` / `0x24D2770` | SymCrypt `GcmEncrypt` / `GcmDecrypt` (`0x24D2BB0` GcmInit checks cbNonce == 12) |
| `0x03FB2E0` / `0x03FB740` | the game's seal / open (vtable `0x25F5BE0` / `0x25F5BD8`); nonce = {prefix qword, seq dword} |
| `0x03FAD50` | AES-GCM cipher constructor; copies a 40-byte `{key[32], prefix[8]}` block and masks it |
| `0x03FA810` | unmasks the block per packet (obfuscated, VM-style; not needed) |
| `0x03FBC60` | cipher factory: type 2 none, 0 raw, >=3 masked AES-GCM |
| `0x03F89E0` | game-connection constructor: **two** ciphers from one 80-byte block, `[0x00:0x28]` -> conn+0x10, `[0x28:0x50]` -> conn+0x18 (one per direction) |

The code around these is obfuscated (junk bytes and opaque predicates between real instructions), so
the direct callers of seal/open were not traced; the direction mapping is left to the next run.

### Result of the `practice_keys` run (capture `6b6a7071901c429b97067ffe68a541d1`, retail)

- **The game seals with the handoff's `+0xAE` key and the `+0x18` u64 as nonce prefix**
  (`client_cipher: key_ae/prefix_u64_18_le`, all 31 packets). The keys are used as sent, so the key
  block is `{+0xAE, +0x18}` for what the game sends, and most likely `{+0xCE, +0x18}` for what it
  receives.
- **The game gave up about 4 s early.** Baseline (`713ac6d1`): first UDP 08:58:43.5, lobby 21802
  `{true}` at :55, then it drops the lobby connection (about 11.5 s). Here: first UDP 09:23:43.9,
  21802 at :51 while it was still sending (about 7.5 s), 31 packets instead of 39.
- **The game paused once, for 0.74 s between its packets 26 and 27**, with no catch-up burst after, so
  the pause was on the game's side. (The 0.78 s gap after packet 0 was the responder loading its AES
  code; it now does that before listening.) The only replies in the two bursts before the pause were
  sealed with key `+0xCE` and prefix `+0x18`: commands `0xF00000A9`..`0xF00000C8`, zero body and ack
  body. So that cipher is very likely the right server-to-game one, and one of those commands looks
  like something the game acts on (plausibly a disconnect or refuse).
- `client_reacted` stayed false because the packet shape never changed, and the early end was not
  flagged because the server stops the responder when the game drops the lobby. The responder now
  records `client_pauses` and `client_ended_early` with the replies sent just before.

### Result of the bisect run (capture `1a4967fc51b24b81a08328c450fe7543`) and a correction

Each of `0xF00000A9`..`C8` went out alone (key `+0xCE`, prefix `+0x18`), one per game packet. No pause,
no new packet shape, 38 packets. And the timing matches the previous run anyway, so **the "early give
up" was not a reaction to a reply**. Measured from the 20600 handoff to the game's 21802:

| capture | handoff keys | replies | handoff -> 21802 |
|---|---|---|---|
| `713ac6d1` | all zero | old responder (its `echo` was validly sealed under the zero keys) | ~12 s |
| `6b6a7071` | probe keys | ~1000 sealed candidates | ~8 s |
| `1a4967fc` | probe keys | 32 single sealed commands | ~8 s |

The 0.74 s pause in `6b6a7071` was most likely an unrelated hitch. What is left: the only run that
lasted longer is the one where every reply was a valid packet carrying the game's own connect command.

### Result of `silent` (`45aea6e5`) and `echo_ce` (`7595fb9d`)

| run | handoff -> 21802 |
|---|---|
| silent (no replies) | 09:36:26.013 -> 33.469 = **7.46 s** |
| echo_ce (the game's connect frame back, sealed `+0xCE` / `+0x18`) | 09:37:26.671 -> 34.061 = **7.39 s** |

No difference. Also: the only long gap in the game's packets lines up with its 21802 each time
(silent 33.06->33.47, echo 33.19->34.06), so a pause simply marks the moment it gives up. From
outside, a sealed echo looks exactly like silence, which cannot tell "wrong key" from "right key,
command ignored". The ~12 s of `713ac6d1` came from its zero-key handoff, not its replies.

### The cipher trace crashed the game (my bug), now fixed

The first cipher trace swapped each AES-GCM cipher object's vtable pointer for a logging copy. The game
uses that pointer as the object's type identity, so swapping it crashed the game as soon as Practice
Range created the ciphers (capture `91967f65`: two ciphers created, game crashed, no seal/open logged).
That was an instrumentation bug, not the game reacting to a reply. Because the trace turned on with the
network log, every `--experiment` run crashed.

Fixed two ways: the trace is now **off by default** (opt-in `OW174_GCM_TRACE=1`), and when on it
**inline-hooks the two functions in place** (seal `0x3FB2E0`, open `0x3FB740`) the same way the Winsock
log hooks ws2_32 -- no object or vtable pointer is touched, so the type check cannot fail. Both
functions start with an identical 12-byte prologue (7 pushes + `mov eax,0x22D0`) with no relative call
inside it, so the 12-byte patch is safe; the hook verifies those bytes before patching.

### Next: trace the game's own seal/open calls (relay)

With the network log on (any `--experiment` run), the relay now also finds every AES-GCM cipher object
(vtable rva `0x25F5BD0`) on the heap and points it at a copy of its vtable whose open/seal log each call
and then call the game's function; the game's code is not modified. `relay/log/wfd.log` gets `GCM seal`
/ `GCM open` lines with the return value, the nine arguments, 48 bytes behind each pointer argument, and
the callers' RVAs for the first calls. That answers directly whether the game tries to open our replies,
whether the open succeeds, and which functions to disassemble next. It needs a relay DLL built from this
source (`relay\build.bat`, or the CI artifact).

### Earlier: `PRACTICE_REPLIES.bat`, test 1 (`silent`) then test 2 (`echo_ce`)

Same `practice_keys` handoff both times. `silent` answers nothing (the keyed timing baseline).
`echo_ce` answers every packet with the game's own connect frame, sealed with key `+0xCE` and the
`+0x18` prefix. If `echo_ce` holds on clearly longer than `silent`, the game accepts packets sealed
that way, which pins the server-to-game cipher and gives a dependable "accepted" signal for the next
steps. The server log now has milliseconds and `state.json` has `first_packet_at`.

### Earlier: `PRACTICE_BISECT.bat` (now test 3 of `PRACTICE_REPLIES.bat`)

Same `practice_keys` handoff, but the responder follows `experiments/replies/bisect_a9_c8.json`: ONE
reply per game packet, key `+0xCE`, prefix `+0x18`, commands `0xF00000B9`..`C8` first, then
`A9`..`B8`. The packet after which the game pauses or gives up names the command
(`state.json`: `client_pauses`, `client_ended_early`). If nothing happens, the early end came from the
volume (several hundred valid packets, or server sequence numbers in the hundreds) rather than one
command, and the next plan tests that instead.

### Earlier: `PRACTICE_TEST.bat` or `PRACTICE_TEST_NORELAY.bat` (plan `practice_keys`)

The plan fills the two key fields and the u64s of 20600 with known probe values
(`gamecrypto.PROBE_*`). The responder (`ow174/matches/responder.py`):

1. identifies which key/prefix the client seals with -> `state.json` `client_cipher`
   (`unknown` means the handoff keys are not used as-is; that is an answer too);
2. answers with correctly sealed candidates for the other direction, most likely first (the other
   key, the same or another prefix, a direction bit), across priority command tags and then the whole
   `0xF00000xx` low byte, each with a zero body and with the client's seq as an ack;
3. records a reaction (new packet shape, new source port, or going quiet early) with the candidates
   sent just before -> `state.json` `reaction` / `client_went_quiet`, and `replies.jsonl`.

Send back `logs/matches/<id>/`, `logs/ow174.log` and `relay/log/wfd.log`. Once a candidate triggers a
reaction, pin it with `OW174_REPLY_PLAN=<file.json>` (a `sealed` entry, see the responder docstring) and
look at what the client sends next: that is the next message to answer.

---

## Earlier notes (before the update above)

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

## Confirmed from the binary: two ciphers, and a fresh session object per connect

Reading the game-server connection constructor (`0x3F89E0`) and its caller (`0x3FF920` @ `0x3FFDBD`):

- The connection holds **two ciphers**: `conn+0x10` from the handoff key block `[0x00:0x28]` and
  `conn+0x18` from `[0x28:0x50]`. The client seals its outbound connect packets with `conn+0x10`
  (the `+0xAE` key, per the captures), so **the server->client direction is `conn+0x18` = the `+0xCE`
  key** with the `+0x18` nonce prefix. This confirms, from the code, the reply cipher we chose.
- Each connect builds a **fresh connection object** (allocated at `0x3FFD84`) from a handoff-derived
  struct: the key block, a couple of 32-bit id fields (`conn+0`, `conn+4`), and a flag. That lines up
  with the community hypothesis that clicking Practice Range "creates another profile" -- it is a new
  per-attempt session object keyed from the handoff. The "different port" is just the fresh UDP socket
  the game opens for it (a new ephemeral local port each attempt, seen in every capture).

What this does NOT yet tell us: what the client accepts as a valid *reply*. The parse/accept code runs
behind the cipher's vtable and the engine's dynamically-resolved socket wrapper -- the same decompile
wall STATE.md hit -- so it has no static caller to follow. The `OW174_GCM_TRACE` inline hook is the
fastest safe way to see whether the client calls `open` on our reply and whether it succeeds.

## One-line summary

Dialing is done and the packet seal is solved (AES-256-GCM; reply cipher = the handoff `+0xCE` key,
prefix `+0x18`, confirmed from the connection constructor). What's left is the client's accept rule for
a reply, which lives behind the socket/cipher-vtable wall; the `OW174_GCM_TRACE` inline hook is the next
safe probe, and a capture from a working 1.74 Practice Range would settle it outright.

## Ghidra pass (2026-09-30): the connect/receive netcode is obfuscated

Ran Ghidra 11.3.2 headless on the decrypted image (`logs/overwatch_image.zip`, base 0x7FF632310000).

Clean, readable decompiles for normal functions. The game-server connection constructor `0x3F89E0`
confirms the two-cipher design: it stores two AES-GCM ciphers built from one key block — the SEND cipher
at object `+0x10` (from block `[0x00:0x28]`) and the RECEIVE cipher at `+0x18` (from block `[0x28:0x50]`),
matching gamecrypto.py. The handoff consumer `0xE3AD2E` copies a 0xE0-byte record and calls the
connection builder `0x3FC550`->`0x3FF920`->`0x3F89E0`.

But the connect/receive netcode itself is anti-decompilation protected:
- `0x3FF920` (connection builder): hundreds of "Unable to resolve constructor" p-code errors, decompiler
  timeout. Control-flow obfuscated.
- `0x7CF230`: overlapping instructions, "bad instruction data", hundreds of unreachable blocks.
- `0x1832F00`: decompiler timeout.
- `0x59ED70`: "Flow exceeded maximum allowable instructions" (the same wall the original notes hit).

So a decompiler cannot read the packet accept/reject logic; the protection defeats static analysis.
The remaining dynamic option that avoids the obfuscation is to hook the CLEAN SymCrypt leaf functions
GcmEncrypt `0x24D2500` / GcmDecrypt `0x24D2770` (the crypto library, not obfuscated) rather than the
game's wrappers: every game-server packet decrypt must pass through GcmDecrypt, so a hook there shows
whether the game ever decrypts our reply, with the key/nonce/plaintext, independent of the obfuscated
wrapper. That is the counterpart to the (mis-aimed) 0x3FB740 wrapper trace.
