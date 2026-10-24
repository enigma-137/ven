# Launch video

A ~67 second, 1080p launch video for VEN, rendered from code: the terminals, captions and
title cards are drawn by `stage.html`, and the dashboard scenes are the **real dashboard**
(`ven ui` against a demo vault), driven by Playwright inside the stage.

Scenes: intro → "secrets end up everywhere" → install / `ven init` / `ven import` →
`ven ui` opens the dashboard (unlock, projects, reveal and copy, switch environments, paste
import with a conflict, settings) → `ven guard` blocking a commit → feature grid →
open-source outro.

## Render

Requirements: `bin/ven` (`make build`), Node with Playwright and Chromium, and `ffmpeg`.

```bash
make build
cd docs/launch-video
node record.js --fps 30 --dsf 2 --out ven-launch.mp4
```

- `--dsf 2` renders at 3840×2160 and downscales to 1920×1080 for crisp text (`--dsf 1` is faster).
- `--shots 26,33.5` also writes `shot-<t>.png` stills at those times; leave out `--out` to only take stills.
- `--to 30` stops early.

`setup-vault.sh` builds a fresh demo vault (fake values only) in `$VEN_DEMO_DIR`
(default `~/.local/share/ven-demo`), starts `ven ui` on port 7420 and prints the launch link;
`record.js` stops that server when it finishes. The vault path appears on the Settings page.

The recorder serves `stage.html` from the dashboard's origin and strips `X-Frame-Options` /
`frame-ancestors` from the dashboard's HTML responses so it can be shown in an iframe. This
happens only inside the recording browser; the shipped server is unchanged.

## Editing

Everything is a function of time in `stage.html`:

- `T` — scene start/end times; `captions` — the headline shown at the top.
- `termScript` / `guardScript` — what the terminals type and print (copied from real output).
- `moves`, `clicks`, `__events` — the cursor path through the dashboard, clicks, and typing.
  Targets are found in the live dashboard by text, `aria-label` or CSS selector.
- `camKeys` — zoom-ins.

The video has no audio track; add music in any editor.
