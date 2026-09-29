# Practice Range experiments

These plans script what the server sends the game after it asks for the Practice Range (message
24000). The goal is to find the reply sequence that makes the game connect to a game server. Nothing
here makes the Practice Range playable yet.

## Run one

```
py -m ow174 --mode retail --experiment practice_sweep
```

or double-click `PRACTICE_TEST.bat`, which runs `practice_sweep`.

Then click Practice Range in the game. Close the game and the black window before trying the next
plan.

| Plan | What it sends |
| --- | --- |
| `practice` | searching state (53000), create-game reply (23320), handoff (20600) with the address in host byte order, then idle again after 20 s if nothing connected |
| `practice_net_order` | the same, with the address and port in network byte order |
| `practice_handoff_only` | only the handoff (20600), to retest the earlier "no traffic" result |
| `practice_sweep` | searching state and create-game reply, then six handoff variants 8 s apart, stopping at the first one the game answers with UDP (see below) |

### Why the sweep

In the second game test the game got the handoff but sent no UDP packets. The earlier plans left most
of the handoff empty: its three IDs, two 64-byte text fields, two 32-byte fields that look like
connection keys, and its last flag. They also set the flag before the address to on, which may mean
"failed" or "cancelled". The sweep tries, in order:

1. every field filled, first flag off, host byte order
2. the same in network byte order
3. every field filled, first flag on, host byte order
4. the same in network byte order
5. only the ID and address, first flag off, host byte order
6. the same in network byte order

"Every field filled" means the three IDs set to the run's token, the address text `127.0.0.1` and
`127.0.0.1:<port>`, two random 32-byte keys, and the last flag on. The log has one line per variant, and
the RESULT line names the variant sent just before the first UDP packet. If the game only reacts to its
first handoff, reorder the steps in `practice_sweep.json`, or keep one variant and delete the rest.

A plan is re-read on every request, so you can edit its JSON while the server runs. To try your own
plan, copy one and start with `--experiment path\to\my_plan.json`. The field list and the
`$ip_host`-style placeholders are explained at the top of `ow174/lobby/experiments.py`.

## What to send back

- `logs/ow174.log`: the `[exp]` lines list each step sent, and end with a `RESULT` line that says
  whether the game sent any UDP packets to the local game server.
- `logs/matches/<id>/packets.jsonl`, if the RESULT says packets arrived.
- `relay/log/wfd.log`: in retail mode, `NET` lines list every address the game connects or sends to.
  A handoff that reaches the wrong address shows up here even when RESULT says no packets.
- `client_msgs.log`: everything the game sent back, such as its 52903 acknowledgement.

## The network log needs a relay DLL built from this source

The relay that START.bat downloads is the upstream release, and it has no `NET` log. Build the DLL
with `relay\build.bat` from an x64 Native Tools prompt, or download the `overwatch-1.74-relay-x64`
artifact from this repo's latest "Windows checks" run, and put it at `relay\owwfd_relay.dll`. The
server uses a DLL that is already there. The log only runs when the server was started with
`--experiment`, and it only exists in retail mode, since tournament mode loads no relay.
