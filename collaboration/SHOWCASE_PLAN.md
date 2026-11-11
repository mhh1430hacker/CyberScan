# ainex-ai.xyz showcase — inspection findings and redesign plan

Author: SHOWCASE (this agent; formerly SENTINEL) · Date: 2026-11-10 · Status: **awaiting owner approval** — nothing implemented.
Repository: `Desktop/dist` (canonical). Inspection was read-only; screenshots were taken from a scratch copy.

## 1. What exists today

**One file, two sites.** `web_v/static/index.html` holds both the main site and the scan workspace. `server.py`
(`page_html`) serves:
- main site (`/`, `ainex-ai.xyz`): the `LANDING` block, with the app markup removed and `js/site.js` instead of `app.js`;
- workspace (`/app.html`, any `scan.*` host): the same file with the `LANDING` block cut out, minus `LANDING_ONLY_CSS`
  (`landing, scroll, science, theme, ask, get-app`) and `LANDING_ONLY_JS` (`gl-hero, pipeline, film, story, landing,
  get-app, lite, scroll, science, ask, sound`).

**Landing sections (in order):** `top` hero (WebGL particle shield) · `film` video · `manifesto` · `how` · `story`
(pinned scroll story: `invoice_2026.pdf.exe` as byte cells → scan beam → vault → rebuilt file) · `pipeline` ·
`science` (entropy histogram, lattice, provenance-labelled figures) · `features` · `repair-sec` · `privacy` ·
stats · CTA. Plus side-dot navigation, language gate (25+ languages, `data-i18n`), lo-fi audio toggle, "Ask the AI"
(`web_v/assistant.py`: Bedrock on Lambda → local Ollama → labelled excerpts from `assistant_knowledge.md`).

**Already good, keep:** `perf.js` low-power tier (`html.perf-low`), reduced-motion handling, the science section's
`ENGINE OUTPUT` / `ILLUSTRATIVE` provenance labels, fast load (DOMContentLoaded about 0.6 s locally, no script errors,
no horizontal overflow at 390 px), a real assistant with an honest fallback.

**Issues found:**
| # | Issue | Evidence |
|---|---|---|
| I1 | The story's risk score **87** and "This looks suspicious" are hard-coded animation values with no ILLUSTRATIVE label: an illustration shown as a measurement. | `story.js:202`, `landing.js:285-289` |
| I2 | The "Ask the AI" button covers the story's last stat chip at 1440×900. | screenshot `s-story` |
| I3 | Mobile hero: the headline sits directly on the particle shield; readability suffers. | screenshot `s-mobile` |
| I4 | About 26,700 px of scroll, with no way to jump to what a visitor cares about. | page height |
| I5 | No guide. Visitors who don't scroll never reach the science or the workspace. | — |
| I6 | Uncommitted edits already exist in `index.html`, `landing.js`, `fx.js`, `scroll.js`, `styles.css` (owner or Guardian). | `git status` |

## 2. Boundaries (how the workspace stays untouched)

- New markup goes **inside the `LANDING` block** only; `page_html` already cuts it from the workspace.
- New scripts/styles are **loaded on demand by `landing.js`** (already landing-only), so `server.py`'s
  `LANDING_ONLY_*` lists need no change: no backend edit, no Guardian coordination needed for routing.
- No changes to `app.js`, `scan.css`, `/api/*`, `server.py`, `assistant.py`, the Android/desktop apps or `detection/`.
- Regression check every stage: render `/app.html` before and after and diff the HTML.

## 3. Redesign plan (incremental; each stage reviewable on its own)

**Stage 0 — Honesty and fixes (small, high value).** Fix I1: the story uses real numbers produced by the engine on the
same harmless demo file. Generate them the way `make_science_data.py` already does, into `data/story.json`, and label
them ENGINE OUTPUT; anything still choreographed gets an ILLUSTRATIVE tag. Fix I2 (move the FAB or reserve its corner)
and I3 (scrim plus a reduced-density shield behind text on small screens).

**Stage 1 — "Interests" (transparent personalization).** A small, visible chooser near the hero:
*File security · Threat detection · How it's built · Just show me around*. The choice:
- reorders/emphasises sections (CSS `order` plus a highlighted path through the side dots), with no content removed;
- sets the depth of explanations (`plain` / `technical`, using the existing "In plain words" pattern);
- is stored in `localStorage` (`cs-interest`), shown as a chip ("Showing: file security · change · reset"), and
  never sent anywhere. No tracking of scroll or behaviour beyond the current page view.

**Stage 2 — The guide robot ("Scout").** A small SVG/CSS character, drawn in the site's purple-glass style:
- docks at the edge of the current section and travels along a path between sections as the visitor scrolls
  (`IntersectionObserver`, transform-only animation); reacts to section changes and hovered demos;
- speaks scripted, section-specific lines (i18n keys, same translation system), asks the interest question,
  offers "Show me" jumps and, at the end, "Open the workspace" → `scan.ainex-ai.xyz`;
- is **scripted, not AI**, and says so ("I'm a guide with prepared notes"); free-form questions go to the existing
  "Ask the AI" panel. Scout replaces the floating FAB as the way into it, which also solves I2;
- can be dismissed (remembered), is keyboard-reachable, has `aria-live="polite"` text, and stays still under reduced motion.

**Stage 3 — Technical storytelling upgrades.** Each demo shows a real mechanism, labelled with its provenance:
- *File inspection:* magic bytes vs extension (`%PDF` vs `MZ`) for the demo file, from engine output;
- *Structural analysis:* PDF object graph with `/OpenAction` → `/JavaScript` highlighted (deflated stream reveal);
- *Suspicious patterns:* URL dissection (`paypa1.com` → homoglyph skeleton → brand match), real `url_intel` output;
- *Tools working together:* evidence from several engines fused into one verdict (noisy-OR, evidence agreement),
  from real output for the demo inputs;
- Canvas 2D / SVG / CSS by default; WebGL only where it already exists (hero). No new dependencies.

**Stage 4 — Visual polish.** Layered glass panels with depth tiers, light falloff tied to scroll, section transitions
(clip-path / view-transition where supported), reusing `theme.css` tokens so the identity stays consistent.

## 4. Performance and accessibility budget

- New JavaScript at most about 25 KB gzipped, loaded after first paint (`requestIdleCallback`). No impact on LCP.
- Transform/opacity animations only; canvases pause off-screen and in hidden tabs; `perf-low` gets static frames.
- `prefers-reduced-motion`: the robot doesn't travel; demos become step-through buttons.
- Text contrast ≥ 4.5:1 over glass; all new controls are keyboard-operable; RTL (Arabic, Urdu, Persian) layout checked.
- Tested at 360, 390, 768, 1024, 1440 and 1920 px; Chromium screenshots each stage; console must stay clean.

## 5. Decisions needed from the owner

1. **Where to work.** `index.html` and four landing files have uncommitted edits (I6), and Guardian is working in the
   same repo. Options: (a) work directly in `Desktop/dist` after Guardian finishes its pass; (b) work in a copy and hand
   over a patch for review (recommended: no collisions); (c) the owner commits the current state first, then (a).
2. **Approve Stage 0** (it changes what the story displays: real numbers instead of 87).
3. **The robot's name and personality** ("Scout" is a placeholder).
4. Which stages to do, and in what order (proposed: 0 → 2 → 1 → 3 → 4).
