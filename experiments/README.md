# Practice Range experiments

These plans script what the server sends the game after it asks for the Practice Range (message
24000). The goal is to find the reply sequence that makes the game connect to a game server. Nothing
here makes the Practice Range playable yet.

## Run one

```
py -m ow174 --mode retail --experiment practice
```

Then click Practice Range in the game. Close the game and the black window before trying the next
plan.

| Plan | What it sends |
| --- | --- |
| `practice` | searching state (53000), create-game reply (23320), handoff (20600) with the address in host byte order, then idle again after 20 s if nothing connected |
| `practice_net_order` | the same, with the address and port in network byte order |
| `practice_handoff_only` | only the handoff (20600), to retest the earlier "no traffic" result |
| `practice_enter` | the `practice` messages that reached "Entering Practice Range", with no reset to idle, and a 90 s wait |
| `practice_found_sweep` | searching, then 8 candidate "game ready" messages, each followed by the handoff |
| `practice_plain_host` | searching, create-game reply, then the handoff with its first field false (not encrypted) and the address as text in the 64-byte field; repeated at 20 s, 60 s wait |
| `practice_state_sweep` | the searching-state message (53000) with states 1 to 9, to see which ones the game accepts (its 52903 answer) |

`PRACTICE_TEST.bat` runs whichever plan is named on its `py` line.

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
