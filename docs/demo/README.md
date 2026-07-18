# Demo Video

**File:** `sentinel-osint-demo.mp4`
**Duration:** 3:00 (180 seconds)
**Resolution:** 1920x1080 (Full HD)
**Codec:** H.264, yuv420p, 24 fps, no audio track
**Size:** ~17 MB

## Structure

| Segment | Time  | Source                | Highlights                                                        |
|---------|-------|-----------------------|-------------------------------------------------------------------|
| Title   | 0:00 - 0:10 | Generated title card   | Sentinel-OSINT wordmark, tagline, 8 data-source badges           |
| Dashboard | 0:10 - 1:00 | `docs/screenshots/dashboard.png` | Exposed-asset discovery, P1-P3 scoring, bulk queue, exports |
| Map     | 1:00 - 1:50 | `docs/screenshots/map.png` | Cached geo-event store, asset pins, cross-border threats, 15-min cache |
| Brief   | 1:50 - 2:40 | `docs/screenshots/brief.png` | Strategic brief, MITRE ATT&CK mapping, CISA KEV cross-ref, proximity feed |
| Outro   | 2:40 - 3:00 | Generated outro card   | Repo URLs + 8-source powered-by grid                              |

## Regenerating

The video is built from the 3 screenshots plus two generated PNG cards
(`title_card.png` and `outro_card.png`). The full build pipeline lives at
`/home/z/my-project/scripts/`:

1. `make_cards.py` - generate the title and outro PNG cards (matplotlib).
2. `rebuild_video.sh` - encode all 5 segments with ffmpeg (libx264 + drawtext
   via `textfile` option for filtergraph-safe text), then concat.

Each screenshot segment has 4 animated text callouts that fade in/out at
specific timestamps to highlight key features. A subtle fade-in/out at each
segment boundary smooths transitions.

## Adding a voiceover

The video is silent by design (no licensed music available). To add a
voiceover:

```bash
# Mux an audio track under the existing video
ffmpeg -i sentinel-osint-demo.mp4 -i voiceover.wav \
  -c:v copy -c:a aac -b:a 192k -shortest sentinel-osint-demo-vo.mp4
```

Or upload the silent MP4 directly to DevPost — silent demos are accepted.
