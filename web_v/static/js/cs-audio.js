/* CyberScan audio engine: one music and one sound set for every page (landing, scan, journey, support).
 *
 * window.CSAudio is the only thing that owns an AudioContext. Everything audible goes through it:
 *   - the music ("Signal Garden"): a generative piece in D, synthesized live, with no files. Warm
 *     voice-led pads (maj9 / m9 / sus colours, a borrowed Gm6 and Bbmaj7 for a cinematic turn), a
 *     round sub bass, an FM glass arpeggio through a ping-pong delay, a slow lead phrase in the
 *     fuller passages, a soft heartbeat pulse and air. Its intensity swells and settles over a
 *     ~7-minute arc, so it never loops audibly.
 *     Its position is the wall clock: every note is a pure function of the time, so any page, any
 *     subdomain, any tab computes the same bar. Opening another page resumes at the same place.
 *   - the journey layer (journey.html): wind that follows the scroll speed, a D pedal and a colour
 *     per stage on top of the same piece, and the journey's events (CSAudio.journey).
 *   - sound effects: one named set (CSAudio.play) for hover, press, toggles, tabs, language,
 *     dialogs, copy, drop, the scan's start / progress / verdicts, errors and page transitions.
 * Preferences (music on/off, volume, effects on/off) live in one cookie, scoped to the parent
 * domain on the real site (scan., j. and the landing share it), with localStorage as the local
 * fallback. Browsers only start audio after a gesture: a remembered "on" fades in (0.6 s) at the
 * synced position on the first click, tap or key.
 * When js/site-nav.js shows another page inside its persistent player frame, that page reuses the
 * shell's engine (same origin), so the music never stops between pages. */
(function () {
  "use strict";
  try {
    const p = window.parent;
    if (p !== window && p.CSAudio && p.CSAudio.host && p.location.origin === location.origin) {
      window.CSAudio = p.CSAudio;
      p.CSAudio.adopt(window);
      return;
    }
  } catch { /* a cross-origin parent: this page plays on its own */ }

  const AC = window.AudioContext || window.webkitAudioContext;
  const midi = (m) => 440 * Math.pow(2, (m - 69) / 12);
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const wall = () => (performance.timeOrigin + performance.now()) / 1000;
  // a deterministic hash in [0,1) of an integer and a salt: the score's only source of "randomness"
  function h(n, salt) {
    let x = (n % 4294967296) | 0;
    x = Math.imul(x ^ Math.imul(salt + 1, 0x9e3779b1), 0x85ebca6b);
    x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35); x ^= x >>> 16;
    return (x >>> 0) / 4294967296;
  }

  /* ---------------- preferences: one cookie for the whole site ---------------- */
  const KEY = "cs-audio";
  const P = { m: 0, v: 0.7, f: 1 };
  function cookieDomain() {
    const host = location.hostname;
    if (!host.includes(".") || /^[\d.]+$/.test(host) || host.endsWith(".localhost")) return "";
    const base = host.replace(/^(www|scan|j)\./, "");
    return base.includes(".") ? `; Domain=.${base}` : "";
  }
  function readPrefs() {
    let raw = "";
    const c = document.cookie.match(/(?:^|;\s*)cs-audio=([^;]+)/);
    if (c) { try { raw = decodeURIComponent(c[1]); } catch { raw = ""; } }
    if (!raw) { try { raw = localStorage.getItem(KEY) || ""; } catch { /* storage off */ } }
    if (raw) {
      const q = new URLSearchParams(raw);
      P.m = q.get("m") === "1" ? 1 : 0;
      const v = parseFloat(q.get("v"));
      if (v >= 0 && v <= 1) P.v = v;
      P.f = q.get("f") === "0" ? 0 : 1;
      return;
    }
    try {   // the old per-page keys
      P.m = localStorage.getItem("cs-sound") === "1" || localStorage.getItem("cs-journey-sound") === "1" ? 1 : 0;
      P.f = localStorage.getItem("cs-ui-sound") === "0" ? 0 : 1;
    } catch { /* storage off */ }
  }
  function writePrefs() {
    const raw = `m=${P.m}&v=${P.v.toFixed(2)}&f=${P.f}`;
    try {
      document.cookie = `${KEY}=${encodeURIComponent(raw)}; Path=/; Max-Age=31536000; SameSite=Lax${cookieDomain()}${location.protocol === "https:" ? "; Secure" : ""}`;
    } catch { /* cookies off */ }
    try { localStorage.setItem(KEY, raw); } catch { /* storage off */ }
  }
  readPrefs();

  const subs = [];
  function emit() {
    for (let i = subs.length - 1; i >= 0; i--) {
      try { subs[i].fn(api); } catch { subs.splice(i, 1); }   // a page that has gone away
    }
  }

  /* ---------------- the graph ---------------- */
  let ctx = null, out = null, musicOut = null, musicBus = null, padF = null, verbIn = null, delayIn = null;
  let fxOut = null, fxDry = null, fxWet = null, noiseBuf = null;
  function hall(sec, decay, pre) {
    const len = Math.floor(ctx.sampleRate * sec), ir = ctx.createBuffer(2, len, ctx.sampleRate), preN = Math.floor(ctx.sampleRate * pre);
    for (let c = 0; c < 2; c++) {
      const d = ir.getChannelData(c); let lp = 0;
      for (let i = preN; i < len; i++) {
        const k = (i - preN) / (len - preN);
        lp += (Math.random() * 2 - 1 - lp) * (0.5 - 0.4 * k);    // darker as it decays
        d[i] = lp * Math.pow(1 - k, decay) * 1.6;
      }
    }
    const conv = ctx.createConvolver(); conv.buffer = ir; return conv;
  }
  function build() {
    if (ctx) return true;
    if (!AC) return false;
    try { ctx = new AC(); } catch { return false; }
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -16; comp.knee.value = 10; comp.ratio.value = 2.5; comp.attack.value = 0.008; comp.release.value = 0.25;
    out = ctx.createGain(); out.gain.value = 1;
    out.connect(comp).connect(ctx.destination);

    // music: sources -> bus -> tone -> level; sends to a long hall and a ping-pong delay
    musicOut = ctx.createGain(); musicOut.gain.value = 0; musicOut.connect(out);
    const tone = ctx.createBiquadFilter(); tone.type = "lowpass"; tone.frequency.value = 9000; tone.Q.value = 0.2;
    musicBus = ctx.createGain(); musicBus.connect(tone).connect(musicOut);
    verbIn = ctx.createGain();
    const verbRet = ctx.createGain(); verbRet.gain.value = 0.8;
    verbIn.connect(hall(4.6, 2.2, 0.03)).connect(verbRet).connect(musicOut);
    delayIn = ctx.createGain();
    const dl = ctx.createDelay(2), dr = ctx.createDelay(2), fb = ctx.createGain(), dlp = ctx.createBiquadFilter(), merge = ctx.createChannelMerger(2), dret = ctx.createGain();
    dl.delayTime.value = dr.delayTime.value = BEAT * 0.75;
    fb.gain.value = 0.36; dlp.type = "lowpass"; dlp.frequency.value = 2400; dret.gain.value = 0.55;
    delayIn.connect(dl); dl.connect(merge, 0, 0); dl.connect(dr); dr.connect(merge, 0, 1); dr.connect(dlp).connect(fb).connect(dl);
    merge.connect(dret); dret.connect(musicOut); dret.connect(verbIn);
    // the pads share one breathing low-pass
    padF = ctx.createBiquadFilter(); padF.type = "lowpass"; padF.frequency.value = 1100; padF.Q.value = 0.6;
    const lfo = ctx.createOscillator(); lfo.frequency.value = 0.045;
    const lfoAmt = ctx.createGain(); lfoAmt.gain.value = 240;
    lfo.connect(lfoAmt).connect(padF.frequency); lfo.start();
    const padSend = ctx.createGain(); padSend.gain.value = 0.55;
    padF.connect(musicBus); padF.connect(padSend).connect(verbIn);

    // effects: their own level and a shorter room
    fxOut = ctx.createGain(); fxOut.gain.value = 0.62; fxOut.connect(out);
    fxDry = ctx.createGain(); fxDry.connect(fxOut);
    fxWet = ctx.createGain(); fxWet.gain.value = 0.34;
    fxWet.connect(hall(2.2, 3, 0.012)).connect(fxOut);

    noiseBuf = ctx.createBuffer(1, ctx.sampleRate * 2, ctx.sampleRate);
    const nd = noiseBuf.getChannelData(0); for (let i = 0; i < nd.length; i++) nd[i] = Math.random() * 2 - 1;
    ctx.addEventListener && ctx.addEventListener("statechange", () => { if (ctx.state === "running") wantPlay(); emit(); });
    return true;
  }
  const running = () => !!ctx && ctx.state === "running";

  /* ---------------- the music ---------------- */
  const BPM = 76, BEAT = 60 / BPM, STEP = BEAT / 2, PER_CHORD = 16;   // 16 eighths = 2 bars per chord
  // [bass, voicing] — voice-led, open, always in the same register
  const PROG = [
    [38, [57, 61, 64, 66]],   // Dmaj9
    [35, [57, 61, 62, 66]],   // Bm9
    [43, [54, 57, 59, 62]],   // Gmaj9
    [45, [52, 57, 59, 64]],   // Asus2
    [42, [52, 57, 61, 64]],   // F#m7
    [43, [54, 59, 61, 62]],   // Gmaj7#11
    [40, [54, 55, 59, 62]],   // Em9
    [45, [55, 59, 62, 64]],   // A7sus4
    [47, [57, 61, 62, 66]],   // Bm9
    [43, [54, 57, 59, 62]],   // Gmaj9
    [42, [57, 62, 64, 66]],   // D/F# add9
    [40, [55, 57, 59, 62]],   // Em11
    [43, [52, 57, 58, 62]],   // Gm6add9 (borrowed: the turn)
    [45, [54, 57, 62, 64]],   // D/A
    [46, [53, 57, 62, 64]],   // Bbmaj7#11 (the cinematic bVI)
    [45, [52, 57, 62, 64]],   // Asus4 -> home
  ];
  const BORROWED = new Set([12, 14]);
  const PENT = [62, 64, 66, 69, 71, 74, 76, 78, 81, 83, 86];
  const WEIGHT = [0.05, 0.9, 0.5, 0.8, 0.3, 0.85, 0.6, 0.95, 0.15, 0.9, 0.45, 0.8, 0.35, 0.7, 0.62, 0.98];
  const CONTOURS = [[0, 1, 2, 3, 4, 3, 2, 1, 0, 2, 4, 5, 4, 2, 3, 1], [0, 2, 1, 3, 2, 4, 3, 5, 4, 3, 2, 4, 1, 3, 0, 2], [5, 4, 3, 2, 3, 1, 2, 0, 1, 3, 2, 4, 3, 5, 4, 2]];
  const MOTIFS = [[0, -1, -2, -1], [0, 1, 0, -2], [-2, -1, 0, 0], [0, -2, -3, -2], [1, 0, -1, -3]];
  let jBias = 0, jTilt = 0;               // the journey's colour
  function intensity(c) {
    const arc = (((c % 64) + 64) % 64) / 64;
    return clamp(0.2 + 0.66 * Math.pow(Math.sin(Math.PI * arc), 1.3) + (h(c, 1) - 0.5) * 0.12 + jBias, 0.08, 1);
  }

  let playing = false, timer = 0, horizon = 0, offset = 0, air = null, duck = 1;
  const live = [];   // sounding pad / bass notes, so a stop can silence them at once
  function syncOffset() { const o = wall() - ctx.currentTime; if (!offset || Math.abs(o - offset) > 0.04) offset = o; }
  const at = (w) => w - offset;
  const level = () => (playing ? 0.34 * P.v * P.v * duck : 0);

  function padNote(m, t, dur, lvl, pan, atk) {
    const g = ctx.createGain();
    g.gain.setValueAtTime(0, t);
    g.gain.setTargetAtTime(lvl, t, atk / 3);
    g.gain.setTargetAtTime(0, t + dur, 0.9);
    const p = ctx.createStereoPanner(); p.pan.value = pan;
    g.connect(p).connect(padF);
    const end = t + dur + 4.5, oscs = [];
    [[-7, "sawtooth", 0.5], [7, "sawtooth", 0.5], [1200, "triangle", 0.22]].forEach(([cents, type, l]) => {
      const o = ctx.createOscillator(); o.type = type; o.frequency.value = midi(m); o.detune.value = cents + (h(m, 3) - 0.5) * 4;
      const og = ctx.createGain(); og.gain.value = l;
      o.connect(og).connect(g); o.start(t); o.stop(end); oscs.push(o);
    });
    live.push({ g, oscs, end });
  }
  function bassNote(m, t, dur, lvl, atk) {
    const g = ctx.createGain();
    g.gain.setValueAtTime(0, t); g.gain.setTargetAtTime(lvl, t, atk / 3); g.gain.setTargetAtTime(0, t + dur, 0.5);
    const lp = ctx.createBiquadFilter(); lp.type = "lowpass"; lp.frequency.value = 260;
    g.connect(lp).connect(musicBus);
    const end = t + dur + 3, oscs = [];
    [[1, 1], [2, 0.18]].forEach(([k, l]) => {
      const o = ctx.createOscillator(); o.type = "sine"; o.frequency.value = midi(m) * k;
      const og = ctx.createGain(); og.gain.value = l; o.connect(og).connect(g); o.start(t); o.stop(end); oscs.push(o);
    });
    live.push({ g, oscs, end });
  }
  function glass(m, t, lvl, decay, pan, bright) {
    const f = midi(m);
    const car = ctx.createOscillator(); car.frequency.value = f;
    const mod = ctx.createOscillator(); mod.frequency.value = f * (bright ? 3.5 : 2);
    const mg = ctx.createGain();
    mg.gain.setValueAtTime(f * (bright ? 0.9 : 1.4), t); mg.gain.exponentialRampToValueAtTime(f * 0.05, t + decay * 0.5);
    mod.connect(mg).connect(car.frequency);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(lvl, t + 0.005); g.gain.exponentialRampToValueAtTime(0.0001, t + decay);
    const p = ctx.createStereoPanner(); p.pan.value = pan;
    car.connect(g).connect(p);
    p.connect(musicBus);
    const ds = ctx.createGain(); ds.gain.value = 0.5; p.connect(ds).connect(delayIn);
    const vs = ctx.createGain(); vs.gain.value = 0.6; p.connect(vs).connect(verbIn);
    car.start(t); mod.start(t); car.stop(t + decay + 0.05); mod.stop(t + decay + 0.05);
  }
  function lead(m, t, dur, lvl) {
    const o = ctx.createOscillator(); o.type = "triangle"; o.frequency.value = midi(m);
    const vib = ctx.createOscillator(); vib.frequency.value = 4.6;
    const vg = ctx.createGain(); vg.gain.setValueAtTime(0, t); vg.gain.linearRampToValueAtTime(midi(m) * 0.004, t + dur * 0.7);
    vib.connect(vg).connect(o.frequency);
    const lp = ctx.createBiquadFilter(); lp.type = "lowpass"; lp.frequency.value = 2200;
    const g = ctx.createGain();
    g.gain.setValueAtTime(0, t); g.gain.setTargetAtTime(lvl, t, 0.09); g.gain.setTargetAtTime(0, t + dur, 0.35);
    o.connect(lp).connect(g);
    g.connect(musicBus);
    const vs = ctx.createGain(); vs.gain.value = 0.9; g.connect(vs).connect(verbIn);
    const ds = ctx.createGain(); ds.gain.value = 0.35; g.connect(ds).connect(delayIn);
    o.start(t); vib.start(t); o.stop(t + dur + 2); vib.stop(t + dur + 2);
  }
  function pulse(t, lvl) {
    const o = ctx.createOscillator(); o.frequency.setValueAtTime(64, t); o.frequency.exponentialRampToValueAtTime(38, t + 0.2);
    const g = ctx.createGain(); g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(lvl, t + 0.006); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.42);
    o.connect(g).connect(musicBus); o.start(t); o.stop(t + 0.45);
  }
  function shaker(t, lvl, pan) {
    const s = ctx.createBufferSource(); s.buffer = noiseBuf;
    const f = ctx.createBiquadFilter(); f.type = "highpass"; f.frequency.value = 7000;
    const g = ctx.createGain(); g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(lvl, t + 0.004); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.06);
    const p = ctx.createStereoPanner(); p.pan.value = pan;
    s.connect(f).connect(g).connect(p).connect(musicBus); s.start(t, Math.random() * 1.5); s.stop(t + 0.08);
  }
  function startAir() {
    if (air) return;
    const s = ctx.createBufferSource(); s.buffer = noiseBuf; s.loop = true;
    const bp = ctx.createBiquadFilter(); bp.type = "bandpass"; bp.frequency.value = 640; bp.Q.value = 0.5;
    const g = ctx.createGain(); g.gain.value = 0.009;
    const lfo = ctx.createOscillator(); lfo.frequency.value = 0.035;
    const la = ctx.createGain(); la.gain.value = 0.006; lfo.connect(la).connect(g.gain);
    s.connect(bp).connect(g); g.connect(musicBus); g.connect(verbIn);
    s.start(); lfo.start();
    air = { s, lfo };
  }
  function stopAir(t) { if (air) { try { air.s.stop(t); air.lfo.stop(t); } catch { /* already stopped */ } air = null; } }

  function chordAt(c, t, len, atk) {
    const k = ((c % 16) + 16) % 16, [bass, voicing] = PROG[k], I = intensity(c);
    voicing.forEach((m, i) => padNote(m, t + i * 0.05, len, 0.034 + (i === 3 ? 0.006 : 0), [-0.4, -0.13, 0.13, 0.4][i], atk));
    bassNote(bass + 12 * (bass < 40 ? 1 : 0), t, len, 0.1 + I * 0.06, atk * 0.6);
    padF.frequency.setTargetAtTime(560 + I * 1500 + jTilt, t, 1.6);
  }
  function step(i, w) {
    const t = at(w);
    if (t < ctx.currentTime - 0.02) return;
    const c = Math.floor(i / PER_CHORD), s = ((i % PER_CHORD) + PER_CHORD) % PER_CHORD, k = ((c % 16) + 16) % 16;
    const I = intensity(c), voicing = PROG[k][1];
    if (s === 0) chordAt(c, t, PER_CHORD * STEP, 1.8);
    // the glass arpeggio: chord tones an octave or two up, following a contour; density follows intensity
    const rot = Math.floor(h(c, 9) * 4) * 2, wgt = WEIGHT[(s + rot) % 16];
    if (wgt < I * 0.95 + (h(i, 3) - 0.5) * 0.08) {
      const pool = voicing.map((m) => m + 12).concat(voicing.slice(2).map((m) => m + 24));
      const idx = CONTOURS[Math.floor(h(c, 5) * 3)][s] % pool.length;
      const accent = s % 4 === 0 ? 1 : 0.72;
      glass(pool[idx], t, (0.024 + I * 0.012) * accent, 1.1 + I * 0.9, (h(i, 4) - 0.5) * 0.9, I > 0.7 && h(i, 6) > 0.6);
    }
    // the lead: a slow phrase in the fuller passages, every other chord
    if (I > 0.55 && c % 2 === 1 && !BORROWED.has(k) && s % 4 === 0) {
      const motif = MOTIFS[Math.floor(h(c, 11) * MOTIFS.length)], top = voicing[3] + 12;
      let base = 0; PENT.forEach((m, j) => { if (Math.abs(m - top) < Math.abs(PENT[base] - top)) base = j; });
      const note = PENT[clamp(base + motif[s / 4], 0, PENT.length - 1)];
      lead(note, t, STEP * 3.4, 0.014 + (I - 0.55) * 0.03);
    }
    // the heartbeat and a breath of shaker at the peaks
    if (I > 0.6 && (s === 0 || s === 6 || s === 8)) pulse(t, s === 6 ? 0.05 : 0.085);
    if (I > 0.76 && s % 2 === 1) shaker(t, 0.004 + (h(i, 8) * 0.003), (h(i, 2) - 0.5) * 0.6);
    // now and then a far, high bell
    if (s % 2 === 1 && h(i, 13) < 0.02 + I * 0.012) glass(voicing[Math.floor(h(i, 14) * 4)] + 24, t, 0.012, 3.2, (h(i, 15) - 0.5) * 1.4, false);
  }
  function tick() {
    if (!playing || !running()) return;
    syncOffset();
    const now = wall(), until = now + 0.5;
    for (let i = live.length - 1; i >= 0; i--) if (live[i].end < ctx.currentTime) live.splice(i, 1);
    if (horizon < now - 1) horizon = now;              // a throttled timer: skip what is already gone
    for (let i = Math.ceil(horizon / STEP); i * STEP < until; i++) step(i, i * STEP);
    horizon = until;
  }
  function startMusic(fade) {
    if (playing || !running()) return;
    playing = true; offset = 0; syncOffset();
    const now = wall(), i = Math.floor(now / STEP), c = Math.floor(i / PER_CHORD);
    const left = (c + 1) * PER_CHORD * STEP - now;
    if (left > 0.8) chordAt(c, ctx.currentTime + 0.01, left, 0.35);     // join the chord in progress
    horizon = now;
    startAir();
    const g = musicOut.gain;
    g.cancelScheduledValues(ctx.currentTime); g.setValueAtTime(Math.max(0.0001, g.value), ctx.currentTime);
    g.setTargetAtTime(level(), ctx.currentTime, fade / 3);
    clearInterval(timer); timer = setInterval(tick, 110); tick();
    emit();
  }
  function stopMusic(fade = 0.5) {
    if (!playing) return;
    playing = false; clearInterval(timer);
    if (!ctx) return;
    const t = ctx.currentTime;
    musicOut.gain.cancelScheduledValues(t); musicOut.gain.setTargetAtTime(0, t, fade / 3);
    live.forEach((n) => { try { n.g.gain.cancelScheduledValues(t); n.g.gain.setTargetAtTime(0, t + fade, 0.05); n.oscs.forEach((o) => o.stop(t + fade + 0.4)); } catch { /* ended */ } });
    live.length = 0;
    stopAir(t + fade + 0.3);
    journeyRelease();
    emit();
  }
  function wantPlay() { if (P.m && running() && !document.hidden) startMusic(0.6); }
  function applyLevel(tc = 0.25) { if (ctx && playing) musicOut.gain.setTargetAtTime(level(), ctx.currentTime, tc); }

  /* ---------------- unlocking (browser autoplay rules) ---------------- */
  function unlock() {
    if (!ctx && !build()) return;
    if (ctx.state !== "running") { const pr = ctx.resume(); if (pr && pr.then) pr.then(wantPlay, () => {}); }
    else wantPlay();
  }
  const gestures = ["pointerdown", "keydown", "touchend"];
  function listen(win) { gestures.forEach((ev) => win.addEventListener(ev, unlock, { capture: true, passive: true })); }
  listen(window);

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { stopMusic(0.3); return; }
    readPrefs();            // another page or subdomain may have changed the switch meanwhile
    emit();
    wantPlay();
  });
  addEventListener("pageshow", (e) => { if (e.persisted) { readPrefs(); emit(); wantPlay(); } });

  /* ---------------- the journey layer ---------------- */
  // the journey's stages: [centre, colour bias, filter tilt, tremolo]
  const STAGES = [[0.08, -0.18, -260, 0], [0.25, -0.02, 0, 2.4], [0.43, 0.08, 250, 0], [0.61, 0.24, 700, 0.4], [0.78, 0.14, 100, 3.2], [0.94, 0.3, 500, 0]];
  let J = null;
  function journeyNodes() {
    if (J) return J;
    const src = ctx.createBufferSource(); src.buffer = noiseBuf; src.loop = true;
    const wf = ctx.createBiquadFilter(); wf.type = "bandpass"; wf.frequency.value = 300; wf.Q.value = 0.8;
    const wind = ctx.createGain(); wind.gain.value = 0;
    src.connect(wf).connect(wind).connect(musicBus); src.start();
    const pedal = ctx.createGain(); pedal.gain.value = 0;
    const trem = ctx.createGain(); trem.gain.value = 1;
    const tl = ctx.createOscillator(); tl.frequency.value = 0.01; const td = ctx.createGain(); td.gain.value = 0;
    tl.connect(td).connect(trem.gain); tl.start();
    const oscs = [38, 45, 50].map((m, i) => { const o = ctx.createOscillator(); o.type = i ? "triangle" : "sine"; o.frequency.value = midi(m); o.detune.value = i * 3; const og = ctx.createGain(); og.gain.value = i ? 0.3 : 1; o.connect(og).connect(trem); o.start(); return o; });
    const plp = ctx.createBiquadFilter(); plp.type = "lowpass"; plp.frequency.value = 500;
    trem.connect(plp).connect(pedal); pedal.connect(musicBus); pedal.connect(verbIn);
    J = { src, wf, wind, pedal, tl, td, oscs, owner: null, lastS: 0 };
    return J;
  }
  function journeyRelease() {
    jBias = 0; jTilt = 0;
    if (!J || !ctx) return;
    const t = ctx.currentTime, j = J; J = null;
    j.wind.gain.setTargetAtTime(0, t, 0.2); j.pedal.gain.setTargetAtTime(0, t, 0.3);
    setTimeout(() => { try { j.src.stop(); j.tl.stop(); j.oscs.forEach((o) => o.stop()); } catch { /* stopped */ } }, 1800);
  }
  function journeyUpdate(s, vel, win) {
    if (!playing) return;
    const j = journeyNodes(); j.owner = win || window;
    const t = ctx.currentTime;
    let wsum = 0, bias = 0, tilt = 0, trem = 0;
    STAGES.forEach(([c, b, tl, tr]) => { const w = clamp(1 - Math.abs(s - c) / 0.17) ** 2; wsum += w; bias += w * b; tilt += w * tl; trem += w * tr; });
    if (wsum > 0) { bias /= wsum; tilt /= wsum; trem /= wsum; }
    jBias = bias; jTilt = tilt;
    padF.frequency.setTargetAtTime(560 + intensity(Math.floor(wall() / STEP / PER_CHORD)) * 1500 + jTilt, t, 0.8);
    j.pedal.gain.setTargetAtTime(s > 0.992 ? 0.02 : 0.05, t, 0.6);
    j.tl.frequency.setTargetAtTime(Math.max(0.01, trem), t, 0.3); j.td.gain.setTargetAtTime(trem > 0.2 ? 0.35 : 0, t, 0.3);
    const v = clamp(Math.abs(vel) * 4.5);
    j.wind.gain.setTargetAtTime(v * 0.16, t, 0.12);
    j.wf.frequency.setTargetAtTime(260 + v * 2600, t, 0.15);
  }

  /* ---------------- effects ---------------- */
  function route(node, rev, dest) {
    const d = ctx.createGain(); d.gain.value = 1 - rev * 0.5; node.connect(d).connect(dest === "music" ? musicBus : fxDry);
    const w = ctx.createGain(); w.gain.value = rev; node.connect(w).connect(dest === "music" ? verbIn : fxWet);
  }
  function tn(f, t, { type = "sine", a = 0.004, d = 0.3, peak = 0.05, glide = 0, rev = 0.4, pan = 0, dest } = {}) {
    const o = ctx.createOscillator(); o.type = type; o.frequency.setValueAtTime(f, t);
    if (glide) o.frequency.exponentialRampToValueAtTime(Math.max(20, f * glide), t + a + d);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(peak, t + a); g.gain.exponentialRampToValueAtTime(0.0001, t + a + d);
    let n = o.connect(g);
    if (pan) { const p = ctx.createStereoPanner(); p.pan.value = clamp(pan, -1, 1); n = n.connect(p); }
    route(n, rev, dest);
    o.start(t); o.stop(t + a + d + 0.05);
  }
  function nz(t, { dur = 0.4, from = 400, to = 3000, q = 1.2, peak = 0.05, a = 0.1, rev = 0.4, type = "bandpass", pan = 0, panTo, dest } = {}) {
    const s = ctx.createBufferSource(); s.buffer = noiseBuf;
    const f = ctx.createBiquadFilter(); f.type = type; f.Q.value = q;
    f.frequency.setValueAtTime(from, t); f.frequency.exponentialRampToValueAtTime(to, t + dur);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(peak, t + a); g.gain.exponentialRampToValueAtTime(0.0001, t + Math.max(a + 0.02, dur));
    let n = s.connect(f).connect(g);
    if (pan || panTo !== undefined) { const p = ctx.createStereoPanner(); p.pan.setValueAtTime(pan, t); if (panTo !== undefined) p.pan.linearRampToValueAtTime(panTo, t + dur); n = n.connect(p); }
    route(n, rev, dest);
    s.start(t, Math.random()); s.stop(t + dur + 0.1);
  }
  function bl(f, t, peak = 0.04, d = 1.4, pan = 0, dest) {
    [[1, 1], [2.01, 0.42], [3.02, 0.2], [4.2, 0.08]].forEach(([k, l]) => tn(f * k, t, { a: 0.003, d: d / Math.sqrt(k), peak: peak * l, rev: 0.65, pan, dest }));
  }
  const HIJAZ = [293.66, 311.13, 369.99, 392.0, 440.0, 466.16, 523.25, 587.33, 622.25, 739.99, 783.99, 880.0];
  const D = (m) => midi(m);
  const FX = {
    // hover: three distinct textures, all tiny
    hoverNav: (t, o) => tn(D(98), t, { d: 0.022, peak: 0.011, rev: 0.15, pan: o.pan }),                                   // D7: a hairline tick
    hoverLink: (t, o) => tn(D(93), t, { type: "triangle", d: 0.03, peak: 0.012, rev: 0.2, pan: o.pan }),                   // A6
    hoverButton: (t, o) => { tn(D(86), t, { type: "triangle", d: 0.04, peak: 0.016, rev: 0.2, pan: o.pan }); tn(D(98), t + 0.012, { d: 0.02, peak: 0.005, rev: 0.2, pan: o.pan }); },
    hoverCta: (t, o) => { nz(t, { dur: 0.16, from: 1800, to: 5200, peak: 0.012, a: 0.08, rev: 0.4, pan: o.pan }); tn(D(81), t, { d: 0.22, peak: 0.01, glide: 1.5, rev: 0.5, pan: o.pan }); },
    hoverCard: (t, o) => { nz(t, { dur: 0.12, from: 2400, to: 4200, q: 2, peak: 0.009, a: 0.05, rev: 0.4, pan: o.pan }); tn(D(90), t + 0.01, { d: 0.12, peak: 0.005, rev: 0.6, pan: o.pan }); },
    // presses
    press: (t, o) => { tn(D(81), t, { type: "triangle", d: 0.045, peak: 0.03, glide: 0.8, rev: 0.15, pan: o.pan }); nz(t, { dur: 0.03, from: 4000, to: 2500, peak: 0.012, a: 0.002, rev: 0.05, type: "highpass", pan: o.pan }); },
    linkPress: (t, o) => tn(D(86), t, { d: 0.07, peak: 0.022, glide: 1.5, rev: 0.3, pan: o.pan }),
    cta: (t, o) => { pulseFx(t, 0.08); bl(D(74), t + 0.01, 0.03, 1.2, (o.pan || 0) * 0.5); bl(D(81), t + 0.07, 0.024, 1.4, (o.pan || 0) * 0.5); nz(t, { dur: 0.35, from: 600, to: 4000, peak: 0.016, a: 0.12, rev: 0.5 }); },
    toggleOn: (t) => { tn(D(81), t, { type: "triangle", d: 0.06, peak: 0.03, rev: 0.3 }); tn(D(86), t + 0.06, { type: "triangle", d: 0.12, peak: 0.028, rev: 0.4 }); },
    toggleOff: (t) => { tn(D(86), t, { type: "triangle", d: 0.06, peak: 0.024, rev: 0.25 }); tn(D(81), t + 0.06, { type: "triangle", d: 0.1, peak: 0.02, rev: 0.3 }); },
    tab: (t, o) => { tn(D(79) * 1.0, t, { d: 0.06, peak: 0.03, glide: 0.7, rev: 0.2, pan: o.pan }); nz(t, { dur: 0.04, from: 1400, to: 900, q: 3, peak: 0.014, a: 0.003, rev: 0.1, pan: o.pan }); },
    lang: (t) => { [78, 81, 86].forEach((m, i) => bl(D(m), t + i * 0.06, 0.018, 1.0, (i - 1) * 0.4)); },
    dialogOpen: (t) => { nz(t, { dur: 0.22, from: 400, to: 2600, peak: 0.022, a: 0.14, rev: 0.4 }); tn(D(74), t + 0.04, { d: 0.18, peak: 0.022, glide: 1.5, rev: 0.5 }); },
    dialogClose: (t) => { nz(t, { dur: 0.2, from: 2400, to: 380, peak: 0.018, a: 0.06, rev: 0.4 }); tn(D(81), t, { d: 0.16, peak: 0.018, glide: 0.67, rev: 0.4 }); },
    copy: (t) => { tn(D(98), t, { d: 0.035, peak: 0.016, rev: 0.4 }); tn(D(101), t + 0.05, { d: 0.06, peak: 0.016, rev: 0.5 }); },
    dragIn: (t) => nz(t, { dur: 0.3, from: 300, to: 1200, peak: 0.016, a: 0.2, rev: 0.4 }),
    drop: (t) => { tn(150, t, { d: 0.25, peak: 0.08, glide: 0.5, rev: 0.2 }); bl(D(74), t + 0.03, 0.026, 1.2); },
    scanStart: (t) => { nz(t, { dur: 0.7, from: 200, to: 4200, peak: 0.05, a: 0.45, rev: 0.5 }); tn(D(57), t, { type: "sawtooth", a: 0.5, d: 0.25, peak: 0.008, glide: 2, rev: 0.6 }); bl(D(86), t + 0.6, 0.02, 1.2); },
    scanTick: (t, o) => tn(D(86 + [0, 2, 4, 7, 9][(o.k || 0) % 5]), t, { d: 0.18, peak: 0.012, rev: 0.6, pan: Math.sin((o.k || 0) * 1.7) * 0.5 }),
    clean: (t) => { [62, 66, 69, 74, 78].forEach((m, i) => bl(D(m), t + i * 0.07, 0.026, 2.2, (i - 2) * 0.25)); tn(D(38), t, { a: 0.1, d: 1.8, peak: 0.05, rev: 0.6 }); },
    review: (t) => { [62, 67, 69, 76].forEach((m, i) => bl(D(m), t + i * 0.08, 0.022, 1.8, (i - 1.5) * 0.3)); },
    threat: (t) => { pulseFx(t, 0.08); tn(D(45), t, { type: "sawtooth", a: 0.02, d: 1.4, peak: 0.016, rev: 0.5 }); tn(D(46), t + 0.01, { type: "sawtooth", a: 0.02, d: 1.4, peak: 0.014, rev: 0.5 }); tn(D(76), t + 0.12, { type: "triangle", d: 0.22, peak: 0.03, rev: 0.4 }); tn(D(70), t + 0.36, { type: "triangle", d: 0.5, peak: 0.028, rev: 0.5 }); },
    error: (t) => { [0, 0.09].forEach((dt) => tn(196, t + dt, { type: "square", d: 0.06, peak: 0.014, rev: 0.1 })); },
    nav: (t) => { nz(t, { dur: 0.42, from: 380, to: 3600, peak: 0.03, a: 0.28, rev: 0.5, pan: -0.6, panTo: 0.6 }); tn(D(74), t + 0.05, { d: 0.35, peak: 0.012, glide: 1.5, rev: 0.7 }); },
    arrive: (t) => { nz(t, { dur: 0.45, from: 3200, to: 500, peak: 0.016, a: 0.05, rev: 0.6, pan: 0.5, panTo: -0.3 }); bl(D(86), t + 0.05, 0.012, 1.4); },
    slider: (t, o) => tn(700 + clamp(o.v || 0) * 1400, t, { type: "triangle", d: 0.018, peak: 0.01, rev: 0.05 }),
    // the landing's own scenes (saudi.js, team.js, toolbox.js, scrolly.js)
    whoosh: (t, o) => nz(t, { dur: o.dur || 0.7, from: o.down ? 2600 : 300, to: o.down ? 260 : 2800, peak: o.peak || 0.07, a: (o.dur || 0.7) * 0.45, rev: 0.45 }),
    rise: (t) => { nz(t, { dur: 1.3, from: 200, to: 5200, peak: 0.055, a: 1.1, rev: 0.5 }); tn(110, t, { type: "sawtooth", a: 1.0, d: 0.4, peak: 0.01, glide: 2, rev: 0.6 }); },
    boom: (t, o) => { tn(o.f || 70, t, { a: 0.004, d: 1.3, peak: 0.26, glide: 0.5, rev: 0.35 }); tn((o.f || 70) * 2, t, { type: "triangle", a: 0.002, d: 0.25, peak: 0.06, glide: 0.6, rev: 0.3 }); nz(t, { dur: 0.35, from: 900, to: 120, peak: 0.1, a: 0.004, rev: 0.5, type: "lowpass", q: 0.7 }); },
    shimmer: (t, o) => { const n = o.n || 7; for (let i = 0; i < n; i++) bl(HIJAZ[((o.from || 0) + i) % HIJAZ.length], t + i * (o.gap || 0.07), 0.03, 1.8, (i / Math.max(1, n - 1) - 0.5) * 0.8); },
    chord: (t) => { [0, 2, 4, 7].forEach((k, i) => bl(HIJAZ[k] / 2, t + i * 0.015, 0.04, 3.2, (i - 1.5) * 0.3)); tn(73.4, t, { a: 0.05, d: 3, peak: 0.06, rev: 0.6 }); },
    pluck: (t, o) => { const f = HIJAZ[(o.k || 0) % HIJAZ.length]; tn(f, t, { type: "triangle", a: 0.002, d: 0.5, peak: 0.055, rev: 0.55, pan: o.pan || 0 }); tn(f * 2, t, { a: 0.002, d: 0.25, peak: 0.02, rev: 0.55, pan: o.pan || 0 }); },
    stamp: (t) => { FX.boom(t, { f: 58 }); bl(HIJAZ[7], t + 0.04, 0.04, 2.6); bl(HIJAZ[4], t + 0.05, 0.032, 2.6); nz(t + 0.02, { dur: 1.6, from: 6000, to: 9000, peak: 0.024, a: 0.01, rev: 0.8, type: "highpass", q: 0.5 }); },
    scan: (t, o) => { tn(1800 + (o.k || 0) * 120, t, { a: 0.01, d: 0.35, peak: 0.018, glide: 1.6, rev: 0.5, pan: o.pan || 0 }); nz(t, { dur: 0.35, from: 3000, to: 7000, peak: 0.016, a: 0.08, rev: 0.3, type: "highpass", q: 0.7 }); },
    tick: (t, o) => tn(2200 + (o.k || 0) * 40, t, { type: "square", a: 0.001, d: 0.025, peak: 0.01, rev: 0.1 }),
    chime: (t) => { bl(D(81), t, 0.032, 1.4); bl(D(86), t + 0.09, 0.028, 1.6); },
    step: (t, o) => tn(HIJAZ[(o.k || 0) % HIJAZ.length] * 2, t, { a: 0.003, d: 0.3, peak: 0.024, rev: 0.5 }),
    soft: (t, o) => FX.hoverCard(t, o),
    open: (t) => FX.dialogOpen(t),
    close: (t) => FX.dialogClose(t),
    success: (t) => { [0, 2, 4].forEach((k, i) => bl(HIJAZ[k + 4], t + i * 0.08, 0.032, 1.2)); },
  };
  function pulseFx(t, peak) { tn(90, t, { d: 0.3, peak, glide: 0.5, rev: 0.15 }); }
  // the journey's events: part of the score, so they follow the music switch
  const HJ = [62, 63, 66, 67, 69, 70, 72, 74];
  const JEV = {
    breach: (t) => { tn(55, t, { d: 1.6, peak: 0.24, glide: 0.5, rev: 0.35, dest: "music" }); nz(t, { dur: 0.9, from: 3000, to: 200, peak: 0.09, a: 0.3, dest: "music" }); tn(D(74), t + 0.05, { d: 2.4, peak: 0.024, rev: 0.9, dest: "music" }); },
    layer: (t, o) => { nz(t, { dur: 0.45, from: 1200 + o.i * 300, to: 5200, peak: 0.04, a: 0.18, dest: "music" }); tn(D(81 + ((o.i * 2) % 7)), t + 0.02, { d: 0.9, peak: 0.016, rev: 0.85, dest: "music" }); },
    ring: (t, o) => tn(D(86 + [0, 2, 4, 7, 9, 12][o.i % 6]), t, { type: "triangle", d: 0.08, peak: 0.014, rev: 0.3, dest: "music" }),
    node: (t, o) => { const m = HJ[o.i % HJ.length]; tn(D(m), t, { type: "triangle", d: 1.1, peak: 0.045, rev: 0.6, dest: "music" }); tn(D(m + 12), t, { d: 0.7, peak: 0.016, rev: 0.7, dest: "music" }); },
    cage: (t) => { tn(90, t, { type: "square", d: 0.18, peak: 0.04, glide: 0.6, rev: 0.4, dest: "music" }); nz(t, { dur: 0.25, from: 900, to: 300, peak: 0.06, a: 0.05, dest: "music" }); tn(D(57), t + 0.08, { d: 1.5, peak: 0.04, rev: 0.6, dest: "music" }); },
    check: (t, o) => tn(D(74 + [0, 2, 4, 7, 9][o.i % 5]), t, { d: 0.25, peak: 0.018, rev: 0.4, dest: "music" }),
    monolith: (t, o) => {
      const sets = [[50, 57, 62], [52, 57, 59], [41, 42, 53]];
      tn(70 - o.i * 8, t, { d: 1.2, peak: 0.18, glide: 0.6, rev: 0.4, dest: "music" });
      sets[o.i % 3].forEach((m, k) => tn(D(m), t + k * 0.02, { type: o.i === 2 ? "sawtooth" : "triangle", d: 2.2, peak: o.i === 2 ? 0.02 : 0.032, rev: 0.6, dest: "music" }));
    },
    whoosh: (t) => nz(t, { dur: 0.7, from: 400, to: 2400, peak: 0.04, a: 0.3, dest: "music" }),
    chime: (t) => { tn(D(74), t, { d: 1.2, peak: 0.028, rev: 0.7, dest: "music" }); tn(D(81), t + 0.09, { d: 1.4, peak: 0.024, rev: 0.7, dest: "music" }); },
    finale: (t) => { [50, 57, 62, 66, 69, 74].forEach((m, k) => tn(D(m), t + k * 0.06, { d: 3.6, peak: 0.036, rev: 0.75, dest: "music" })); tn(73.4, t, { d: 3.5, peak: 0.1, rev: 0.4, dest: "music" }); },
  };
  const GAP = { hoverNav: 45, hoverLink: 45, hoverButton: 55, hoverCta: 160, hoverCard: 90, press: 40, linkPress: 60, slider: 32, scanTick: 140, tick: 55, soft: 90, scan: 90, step: 90, whoosh: 380, rise: 900, boom: 500, stamp: 900, shimmer: 600, chord: 1200, pluck: 80, chime: 300, nav: 300, ring: 40, check: 50, node: 90, layer: 300, clean: 900, threat: 900, review: 900 };
  const GROUP = { open: "dlg", close: "dlg", dialogOpen: "dlg", dialogClose: "dlg", hoverNav: "hov", hoverLink: "hov", hoverButton: "hov", hoverCard: "hov", hoverCta: "hov" };
  const last = {};
  let budget = 0, budgetAt = 0;
  function gate(name, opts) {
    const now = performance.now(), key = (GROUP[name] || name) + (opts.key ?? "") + (opts.i ?? "");
    if (now - (last[key] || 0) < (GROUP[name] === "dlg" ? 150 : GAP[name] || 110)) return false;
    if (now - budgetAt > 500) { budget = 0; budgetAt = now; }
    if (++budget > 10) return false;     // never more than 10 sounds in half a second
    last[key] = now;
    return true;
  }
  function play(name, opts = {}) {
    if (!P.f || !FX[name] || !running() || document.hidden) return;
    if (!gate(name, opts)) return;
    try { FX[name](ctx.currentTime + 0.005, opts); } catch { /* the graph refused: stay silent */ }
  }
  function journeyEvent(name, opts = {}) {
    if (!playing || !JEV[name] || !running() || document.hidden) return;
    if (!gate("j" + name, opts)) return;
    try { JEV[name](ctx.currentTime + 0.01, opts); } catch { /* refused */ }
  }

  /* a soft pad that follows a level (0..1): the "Made by Saudi hands" scene */
  let droneNodes = null;
  function drone(lvl) {
    if (!running()) return;
    const target = P.f && !document.hidden ? clamp(lvl) * 0.04 : 0;
    if (!droneNodes) {
      if (target <= 0.0005) return;
      const g = ctx.createGain(); g.gain.value = 0.0001;
      const lp = ctx.createBiquadFilter(); lp.type = "lowpass"; lp.frequency.value = 700; lp.Q.value = 0.4;
      const oscs = [73.42, 110.0, 146.83, 220.0 * 1.003].map((f, i) => { const o = ctx.createOscillator(); o.type = i % 2 ? "triangle" : "sawtooth"; o.frequency.value = f; o.detune.value = (i - 1.5) * 6; o.connect(lp); o.start(); return o; });
      const lfo = ctx.createOscillator(); lfo.frequency.value = 0.07; const lg = ctx.createGain(); lg.gain.value = 260; lfo.connect(lg).connect(lp.frequency); lfo.start();
      lp.connect(g); route(g, 0.6);
      droneNodes = { g, oscs: [...oscs, lfo] };
    }
    droneNodes.g.gain.setTargetAtTime(Math.max(0.0001, target), ctx.currentTime, 0.35);
    clearTimeout(droneNodes.stop);
    if (target <= 0.0005) droneNodes.stop = setTimeout(() => { if (droneNodes && droneNodes.g.gain.value < 0.001) { droneNodes.oscs.forEach((o) => o.stop()); droneNodes = null; } }, 2500);
  }
  document.addEventListener("visibilitychange", () => { if (document.hidden) drone(0); });

  /* ---------------- the interface ---------------- */
  const api = {
    host: true,
    get music() { return !!P.m; },
    get fx() { return !!P.f; },
    get volume() { return P.v; },
    get unlocked() { return running(); },
    get context() { return ctx; },
    musicPlaying: () => playing && running(),
    setMusic(v) {
      P.m = v ? 1 : 0; writePrefs();
      if (P.m) unlock(); else stopMusic(0.5);
      emit();
    },
    setFx(v) { P.f = v ? 1 : 0; writePrefs(); if (P.f) unlock(); emit(); },
    setVolume(v) { P.v = clamp(Number(v) || 0); writePrefs(); applyLevel(0.08); emit(); },
    setDuck(k) { duck = clamp(Number(k)); applyLevel(0.3); },
    onChange(fn, win) { subs.push({ fn, win: win || window }); },
    unlock,
    play,
    drone,
    /* where the piece is, for anyone who wants to show it (seconds into the 16-chord cycle) */
    position: () => { const s = wall() % (STEP * PER_CHORD * 16); return { seconds: s, chord: Math.floor(s / (STEP * PER_CHORD)) }; },
    journey: { update: journeyUpdate, event: journeyEvent, release: journeyRelease },
    /* a page shown inside the persistent player (js/site-nav.js) uses this engine */
    adopt(win) {
      listen(win);
      win.addEventListener("pagehide", () => {
        for (let i = subs.length - 1; i >= 0; i--) if (subs[i].win === win) subs.splice(i, 1);
        if (J && J.owner === win) journeyRelease();
        gestures.forEach((ev) => win.removeEventListener(ev, unlock, { capture: true }));
      });
    },
  };
  window.CSAudio = api;
  // a browser that already allows sound (Firefox's policy API) starts at once
  try { if (P.m && navigator.getAutoplayPolicy && navigator.getAutoplayPolicy("audiocontext") === "allowed") unlock(); } catch { /* no policy API */ }
})();
