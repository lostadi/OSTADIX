# Boxing: injury inspection and O-node matches

`examples/boxing.O` is a self-contained boxing simulation. Run the same example
locally or assign the red and blue fighters to authenticated O-node machines.
Every run saves an injury timeline and a match result that can be examined after
the animation ends.

```sh
cd /path/to/ostadix-BM/examples
O boxing.O
```

The terminal displays the fight and its result. The printed artifact location
contains `report.html`, an interactive injury inspector, and `match.json`, its
complete data. Open `report.html` in a browser; it works offline without a web
server or external assets. The example remains one file: the other machine does
not need a separately installed boxing script.

By default, reports are saved beneath
`$XDG_STATE_HOME/ostadix/boxing`, or `~/.local/state/ostadix/boxing` when that
variable is unset, in a directory unique to the match. An existing report is
preserved when an explicit output directory is reused. `engine.O` records the
executed engine source; a remote match also saves `nodes.json` and the individual
node receipts beneath `receipts/`.

To choose a stable output location and run without terminal animation:

```sh
OSTADIX_BOXING_HEADLESS=1 \
OSTADIX_BOXING_OUT="$PWD/boxing-result" \
O boxing.O
```

## Examine injuries

During terminal playback, press **1** for Titan's magnified face and injury
readout, **2** for Phantom's, or **i** to examine both fighters. Examination
pauses the match. **Space** pauses or resumes, and **q** or **Ctrl-C** ends the run with an
interrupted result; it does not award a winner.

The replay preserves both fighters at every simulation tick. Select a fighter,
scrub the timeline, and select a body region to examine its condition. The
enlarged sprite shows the game's injury overlays; the numerical panel includes
both eyes, both eyebrow cuts, nose damage, jaw/concussion damage, liver and rib
trauma, blood loss, and mouthguard state. Injury events connect a change to its
tick and, where applicable, the opponent, punch, hit region, and damage.

The values are an arcade simulation model. They describe the rules used by this
example, rather than clinical diagnoses or medically calibrated measurements.
The data file keeps the recorded values, including values above a display bar's
range, so the visual presentation does not discard accumulated damage.

In the replay, use the full-body, face, or torso view; click the sprite or an
anatomical region button to focus the metrics and event list. Select a metric to
see its complete history. Event buttons jump back to the corresponding state.
The timeline has play/pause, single-tick steps, and a speed control. Keyboard
shortcuts are Space for playback, left/right arrows for ticks, and 1/2 for the
fighter selection when focus is outside a form control.

## Machine versus machine

Each participating host needs a working O evaluator, its Python backend, and
the native `o-node` service. The coordinator also needs `octl`. Start the normal
node service on each host using the existing Ostadix installation:

```sh
o node start
```

Pair the coordinator with each fighter host through the normal one-use-passcode
flow. On the offering host, run `o node pair`; on the coordinator, run
`o node pair OFFERING_NODE_ID` and enter that host's displayed passcode. Existing
pairings can be reused. List identities from the coordinator:

```sh
octl node list
```

Assign the two paired node IDs to the corners, then run the ordinary example:

```sh
OSTADIX_BOXING_RED_NODE=red-machine-node-id \
OSTADIX_BOXING_BLUE_NODE=blue-machine-node-id \
OSTADIX_BOXING_OUT="$PWD/machine-match" \
O boxing.O
```

A local fighter can also face a remote host:

```sh
OSTADIX_BOXING_RED_NODE=local \
OSTADIX_BOXING_BLUE_NODE=opponent-node-id \
O boxing.O
```

Use `OSTADIX_BOXING_RED_ADDRESS=HOST:PORT` and
`OSTADIX_BOXING_BLUE_ADDRESS=HOST:PORT` only when a paired host needs an explicit
route. These override routing while retaining the paired identity; they do not
replace authentication. The ordinary hosted-operation port is TCP 7337 and the
pairing port is TCP 7340. See [the LAN pairing guide](ZERO_CONFIG_LAN.md) for the
underlying node setup.

## What each machine computes

At a tick boundary, the coordinator sends the same committed world snapshot to
both fighter workers. Each worker computes its own fighter's decision, movement,
traction, rope rebound, and ragdoll update. A reply identifies the match, tick,
fighter, and exact input snapshot. The coordinator accepts both replies before
committing either fighter's state, then resolves shared collisions, injuries,
ring effects, referee decisions, round scoring, and the next world snapshot.
Shared body contact separates the fighters and combines their horizontal
momentum when they move into each other, preventing their bodies from passing
through one another.

This gives the two fighters independent device execution without allowing reply
arrival order to determine which fighter sees a newer world. The coordinator is
the authoritative referee. It is not a peer-consensus or adversarial anti-cheat
system.

Workers are complete O documents submitted through `octl node run`; each request
starts a fresh evaluator. Fighter and world data cross the node boundary as
explicit JSON state. No hidden Python process state is assumed to persist
between requests. Local and remote fighters use the same computation function.
Native receipts preserve evidence of remote execution.

A node error or timeout stops advancement and preserves an incomplete match.
The coordinator does not silently replace a missing remote fighter with a local
one, retry an operation whose completion is unknown, or declare the other side
the winner because of a transport failure.

## Match completion and controls

A normal run continues until a knockout, physician stoppage, or the configured
rounds have been scored. A tied score is an explicit draw. An interrupted run,
configured tick limit, or failed node operation has no official winner.

The judges reward **damage and finishing danger**. Each fighter's score is the
total HP damage they caused plus their accumulated finishing-danger index.
Blocked hits count their actual HP damage. The danger component rewards injury
changes that threaten to end the simulated fight, using these game weights:

| Inflicted change | Added finishing danger |
| --- | ---: |
| Jaw/concussion damage | 1.5 × increase |
| Liver trauma | 1.25 × increase |
| Rib trauma | 0.5 × increase |
| Nose damage | 0.25 × increase |
| Left and right eye swelling | 0.25 × combined increase |
| Left and right brow cuts | 0.15 × combined increase |
| Knockdown | 20 per knockdown inflicted |

The delayed liver-collapse effect also credits the opponent with the actual HP
lost and a knockdown's danger bonus. Each round's card records its damage,
finishing danger, and combined contribution. The higher cumulative total wins
when the scheduled rounds end; equal totals within numerical tolerance are a
draw. KO and physician-stoppage
results still end the match immediately. Punch count alone does not decide a
scorecard, and corner treatment does not erase damage already inflicted.

This finishing-danger index is the game's interpretation of “lethalness”: a
measure of simulated stopping pressure, not a mortality estimate. The complete
score breakdown remains available in `match.json` and the injury inspector.

Configuration is read from the coordinator's environment:

| Variable | Purpose |
| --- | --- |
| `OSTADIX_BOXING_RED_NODE` | Paired red fighter node ID, or `local` (default). |
| `OSTADIX_BOXING_BLUE_NODE` | Paired blue fighter node ID, or `local` (default). |
| `OSTADIX_BOXING_RED_ADDRESS` | Optional explicit address for the paired red node. |
| `OSTADIX_BOXING_BLUE_ADDRESS` | Optional explicit address for the paired blue node. |
| `OSTADIX_BOXING_SEED` | Deterministic match seed; default `42`. |
| `OSTADIX_BOXING_ROUNDS` | Number of scheduled rounds; default `3`. |
| `OSTADIX_BOXING_ROUND_SECONDS` | Simulated duration of each round, at four ticks per second; default `60`. |
| `OSTADIX_BOXING_MAX_TICKS` | Optional execution limit; reaching it records an incomplete match. |
| `OSTADIX_BOXING_HEADLESS=1` | Disable animation for scripts and unattended runs. |
| `OSTADIX_BOXING_DELAY` | Delay in seconds between displayed frames; default `0.065`. |
| `OSTADIX_BOXING_OUT` | Directory receiving the report, data, and execution evidence. |
| `OSTADIX_BOXING_NODE_TIMEOUT` | Per-operation node time budget in seconds; default `30`. |
| `OSTADIX_BOXING_OCTL` | Optional path to the coordinator's native `octl` executable. |

For a short transport check, use one four-second round. It may end in a draw
because the fighters have had little time to reach each other:

```sh
OSTADIX_BOXING_HEADLESS=1 \
OSTADIX_BOXING_ROUNDS=1 \
OSTADIX_BOXING_ROUND_SECONDS=4 \
OSTADIX_BOXING_RED_NODE=red-machine-node-id \
OSTADIX_BOXING_BLUE_NODE=blue-machine-node-id \
O boxing.O
```

The behavioral regression suite loads the engine definitions from the actual
example and checks state transfer, atomic tick commits, outcomes, and injury
exports:

```sh
python3 -m unittest tests.test_boxing
```

These unit tests do not themselves prove cross-device operation. A real O-node
transport check must use authenticated node services, and a two-node loopback
test must be distinguished from execution on two physical machines.

An explicit macOS/Linux terminal regression starts native O in an isolated PTY,
checks complete frames and each examination view, then verifies that both `q`
and Ctrl-C save an interrupted result and restore canonical input, echo, and
terminal signals. It uses temporary output and runs only when invoked directly:

```sh
python3 tests/test_boxing_terminal.py --o-bin /path/to/native/O
```
