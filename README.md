# glyphgate — catch homograph & invisible-char traps in ENS names (offline)

**glyphgate** helps wallets, dapps, and marketplaces **spot sketchy ENS labels**
before displaying or storing them. It flags Unicode **homoglyph confusables**,
**invisible/formatting characters**, and **mixed-script bait** (Latin+Greek/
Cyrillic). It also provides an **ASCII-safe suggestion** you can log or show.

No RPC. No web calls. Pure Unicode analysis.

## Why this matters

- `vitalík.eth` vs `vitalik.eth` — a single `í` can trick the eye.
- `аrtblocks.eth` — first `a` is **Cyrillic** (U+0430), not Latin.
- `pay⟨ZWSP⟩ment.eth` — hidden zero-width space in the middle.
- `0xDeaDBeef` styled as `0xDEADBEEF` with visually confusable letters/digits.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
