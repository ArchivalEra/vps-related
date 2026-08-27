# tmux session sharing playbook (human + agent, one screen)

Purpose: let the user and the ZCode agent see and drive the SAME terminal
session. One tmux session acts as the shared blackboard.

Verified locally on this workstation (Debian forky/sid, tmux 3.7b),
2026-08-26 — commands below are copy-paste tested.

## Core rule

The agent NEVER attaches as a client. It reads with `capture-pane` and types
with `send-keys` from plain shell calls. Attaching a second client would
resize the window to the smallest terminal (the agent has none), fighting
the human's view. Detached operation also survives between agent tool calls.

## Same host (this workstation)

```bash
# --- setup (once per working session) ---
tmux new-session -d -s pair -x 200 -y 50   # fixed size until someone attaches

# --- human side (any local terminal / Konsole tab) ---
tmux attach -t pair        # or: tmux new -A -s pair  (attach-or-create)

# --- agent side (harness Bash calls) ---
tmux ls                                   # list sessions
tmux capture-pane -p -t pair              # read current screen (-p = plain text)
tmux capture-pane -p -t pair -S -100      # read last 100 lines of scrollback
tmux send-keys -t pair 'uname -a' Enter   # type a command into the pane
```

Optional: mirror everything to a log file while work happens:

```bash
tmux pipe-pane -o -t pair 'cat >> /tmp/pair.log'
```

## Remote host (VPS over the human's own SSH)

Security model: the agent NEVER gets VPS credentials and never connects to
the VPS itself. The shared tmux session lives ON THIS WORKSTATION; the
human's interactive `ssh` command runs INSIDE one of its panes. Whatever the
human sees on the VPS renders into that pane, so reading the pane == reading
the VPS screen. Agent keystrokes sent to the pane flow through the human's
authenticated ssh session.

```bash
# --- human (one-time per working session, any local terminal) ---
tmux new -A -s pair          # create-or-attach local session named 'pair'
ssh <vps>                    # normal login inside the pane, own credentials
tmux attach || tmux new -s work   # optional inner tmux ON THE VPS: survives ssh drops

# --- agent (harness Bash calls, purely local operations) ---
tmux capture-pane -p -t pair              # read the VPS screen
tmux capture-pane -p -t pair -S -100      # scrollback
tmux send-keys -t pair './build.sh' Enter # type; goes through their ssh to the VPS
```

Two layers, two jobs: outer tmux (workstation) is the share medium; inner
tmux (VPS) is drop-protection. Prefix-key collisions: change one side's
prefix (e.g. inner: `tmux set -g prefix C-a`) or use only the outer one.

Prerequisite note: the agent reads/writes the LOCAL pane only — works with
zero network setup, verified 2026-08-26.

## Rules of engagement

1. Session name is `pair` unless agreed otherwise. `tmux ls` before attaching;
   reuse an existing session, do not spawn duplicates.
2. Roles are explicit: whoever types announces it ("driving now"). The other
   side observes.
3. Human detaches with `C-b d`. Never leave via `exit` — that kills the
   session for everyone. Killing a session (`tmux kill-session -t pair`) only
   by explicit agreement.
4. The agent always targets an exact pane (`-t pair:0.0`) and never sends
   blind control characters (C-c / C-d) — those hit whatever is focused.
5. Long jobs (kernel builds) run INSIDE the shared session, so output stays
   visible across detach/disconnect and both sides can check progress.
6. This workstation reboots without warning: tmux sessions die with it.
   Anything important must land in files/logs, not just the pane.

## Demo transcript (2026-08-26, local)

```console
$ tmux new-session -d -s pair-demo -x 200 -y 50
$ tmux send-keys -t pair-demo 'echo HELLO-FROM-AGENT; hostname; date' Enter
$ tmux capture-pane -p -t pair-demo | tail -4
archivalera@shit-microsoft:~/plum/zcode-projects/vps-related$ echo HELLO-FROM-AGENT; hostname; date
HELLO-FROM-AGENT
shit-microsoft
2026-08-26 CST
$ tmux ls          # separate shell call later — server survived
pair-demo: 1 windows (created Wed Aug 26 20:46:41 2026)
```

The `pair-demo` session was left running for hands-on practice: attach from
any local terminal with `tmux attach -t pair-demo`.
