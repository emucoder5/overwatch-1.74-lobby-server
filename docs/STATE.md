# Project state

## Works

- Login, the main menu, the lobby hero and lobby scenes (events).
- Loot boxes: all 11 types can be opened.
- The shop: prices come from the catalog, and each item takes the right currency (credits, league tokens or competitive points).
- The three Anniversary Remix scenes.
- The dashboard: profile, events, loot boxes, shop and skins.

## Partly works

- Weekly challenges (Tracer, Symmetra): the data is in place, but the game does not pick them up on its own, and their banner and popup do not show.
- Practice Range and matchmaking: the game sends its requests (24000 for the Practice Range, 44100 to search, 44102 to cancel), and the server starts or stops a worker for each. No match actually starts.
- `tools/probe_practice.py` can put the game into the "searching" state (message 53000 with state 4, answered by 52903). It resets the game back to idle afterwards.
- `--experiment <plan>` answers the Practice Range request with a scripted sequence (see `experiments/README.md`): 53000, then the create-game reply candidate 23320, then the handoff 20600 pointing at the local instance, in either byte order. It logs whether the game sent UDP packets, and in retail mode the relay logs every address the game dials. Tried against the game: it answers 53000 with 52903 = false, and after the handoff it opens no new socket and sends nothing to any address (the relay's network log hooks Winsock itself). So the handoff is ignored as sent, whatever the byte order; the next plan sweeps the 53000 state values.

## Does not work yet

- Joining a match. Sending a server address (message 20600) gave no network traffic from the game. That test only watched the local game server, so a wrongly encoded address would have looked the same; the experiment plans retest it with both byte orders and the relay's network log.
- Competitive seasons.

Do not describe this server as able to play matches.

## Data

`data/` holds message layouts and catalogs taken from a 1.68 reference capture and the 1.74 client. Player names in it are anonymized. The raw captures are not included. `ow174/bnet/descriptors.pb` is Battle.net protocol data the server needs; it is not a program.
