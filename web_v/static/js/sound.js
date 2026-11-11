/* Calm lo-fi, generated live: no vocals, no files, no samples.
 *
 * ~72 BPM with a light swing. Soft electric-piano chords (two detuned sines
 * per note, a little tremolo, a warm low-pass), a round sine bass, a muffled
 * kick, a brushed snare, very quiet hats, and vinyl crackle underneath.
 * A slow 4-chord loop: Fmaj9 · Em7 · Dm9 · Cmaj7, two bars each.
 *
 * Off by default; the choice is remembered. No sound effects anywhere else.
 */
(function () {
  "use strict";
  const { t } = window.CS;
  const buttons = [...document.querySelectorAll(".sound-btn")];
  const BPM = 72, BEAT = 60 / BPM, STEP = BEAT / 4; // sixteenth notes
  const SWING = 0.18;
  // MIDI notes, voiced close and low for warmth
  const CHORDS = [
    [41, 53, 57, 60, 64, 67], // Fmaj9  (F2 | F3 A3 C4 E4 G4)
    [40, 52, 55, 59, 62],     // Em7
    [38, 50, 53, 57, 60, 64], // Dm9
    [36, 48, 52, 55, 59],     // Cmaj7
  ];
  const freq = (m) => 440 * Math.pow(2, (m - 69) / 12);

  let on = false, ctx = null, master = null, keysBus, drumBus, crackle, timer = 0, nextTime = 0, step = 0, duck = 1;
  try { on = localStorage.getItem("cs-sound") === "1"; } catch { /* storage off */ }

  function build() {
    ctx = new (window.AudioContext || window.webkitAudioContext)();
    master = ctx.createGain(); master.gain.value = 0;
    const tape = ctx.createBiquadFilter(); tape.type = "lowpass"; tape.frequency.value = 3800; tape.Q.value = 0.4;
    const comp = ctx.createDynamicsCompressor(); comp.threshold.value = -24; comp.ratio.value = 3;
    master.connect(tape).connect(comp).connect(ctx.destination);

    keysBus = ctx.createGain(); keysBus.gain.value = 0.55;
    const warm = ctx.createBiquadFilter(); warm.type = "lowpass"; warm.frequency.value = 1500;
    // tremolo
    const trem = ctx.createGain(); trem.gain.value = 0.85;
    const lfo = ctx.createOscillator(); lfo.frequency.value = 4.2;
    const lfoAmt = ctx.createGain(); lfoAmt.gain.value = 0.12;
    lfo.connect(lfoAmt).connect(trem.gain); lfo.start();
    keysBus.connect(warm).connect(trem).connect(master);

    drumBus = ctx.createGain(); drumBus.gain.value = 0.7;
    const drumLP = ctx.createBiquadFilter(); drumLP.type = "lowpass"; drumLP.frequency.value = 2600;
    drumBus.connect(drumLP).connect(master);

    // vinyl crackle: a looping buffer of soft hiss and sparse clicks
    const len = ctx.sampleRate * 4;
    const buf = ctx.createBuffer(1, len, ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) {
      d[i] = (Math.random() * 2 - 1) * 0.012;
      if (Math.random() < 0.0004) d[i] += (Math.random() * 2 - 1) * 0.5;
    }
    crackle = ctx.createBufferSource(); crackle.buffer = buf; crackle.loop = true;
    const cg = ctx.createGain(); cg.gain.value = 0.35;
    const hp = ctx.createBiquadFilter(); hp.type = "highpass"; hp.frequency.value = 900;
    crackle.connect(hp).connect(cg).connect(master); crackle.start();
  }

  function note(m, time, dur, level) {
    [0, 7].forEach((det, k) => {
      const o = ctx.createOscillator();
      o.type = "sine";
      o.frequency.value = freq(m);
      o.detune.value = k ? det : -det;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, time);
      g.gain.exponentialRampToValueAtTime(level, time + 0.02);
      g.gain.exponentialRampToValueAtTime(level * 0.35, time + 0.4);
      g.gain.exponentialRampToValueAtTime(0.0001, time + dur);
      o.connect(g).connect(keysBus);
      o.start(time); o.stop(time + dur + 0.05);
    });
  }

  function bass(m, time, dur) {
    const o = ctx.createOscillator(); o.type = "sine"; o.frequency.value = freq(m);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, time);
    g.gain.exponentialRampToValueAtTime(0.22, time + 0.03);
    g.gain.exponentialRampToValueAtTime(0.0001, time + dur);
    o.connect(g).connect(master); o.start(time); o.stop(time + dur + 0.05);
  }

  function kick(time) {
    const o = ctx.createOscillator(); o.type = "sine";
    o.frequency.setValueAtTime(110, time);
    o.frequency.exponentialRampToValueAtTime(42, time + 0.18);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.5, time);
    g.gain.exponentialRampToValueAtTime(0.0001, time + 0.32);
    o.connect(g).connect(drumBus); o.start(time); o.stop(time + 0.35);
  }

  function noiseHit(time, dur, type, f, level) {
    const len = Math.floor(ctx.sampleRate * dur);
    const buf = ctx.createBuffer(1, len, ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / len, 3);
    const src = ctx.createBufferSource(); src.buffer = buf;
    const fl = ctx.createBiquadFilter(); fl.type = type; fl.frequency.value = f; fl.Q.value = 0.8;
    const g = ctx.createGain(); g.gain.value = level;
    src.connect(fl).connect(g).connect(drumBus); src.start(time);
  }

  function schedule() {
    while (nextTime < ctx.currentTime + 0.25) {
      const bar = Math.floor(step / 16), s16 = step % 16;
      const chord = CHORDS[Math.floor(bar / 2) % CHORDS.length];
      const swing = s16 % 2 ? STEP * SWING : 0;
      const time = nextTime + swing;
      if (s16 === 0 && bar % 2 === 0) {
        chord.slice(1).forEach((m, i) => note(m, time + i * 0.035, BEAT * 7.5, 0.05));
        bass(chord[0] - 12 + 12, time, BEAT * 1.8);
      }
      if (s16 === 10 && bar % 2 === 0) chord.slice(2, 5).forEach((m, i) => note(m + 12, time + i * 0.05, BEAT * 1.6, 0.022));
      if (s16 === 8) bass(chord[0], time, BEAT * 1.2);
      if (s16 === 0 || s16 === 7 || (s16 === 10 && bar % 2)) kick(time);
      if (s16 === 4 || s16 === 12) noiseHit(time, 0.22, "bandpass", 1900, 0.16);
      if (s16 % 2 === 0) noiseHit(time, 0.04, "highpass", 8000, s16 % 4 === 2 ? 0.05 : 0.025);
      nextTime += STEP;
      step++;
    }
  }

  function set(value, persist = true) {
    on = value;
    if (persist) { try { localStorage.setItem("cs-sound", on ? "1" : "0"); } catch { /* storage off */ } }
    if (on && !ctx) build();
    if (ctx) {
      if (on) {
        ctx.resume();
        nextTime = ctx.currentTime + 0.1;
        clearInterval(timer);
        timer = setInterval(schedule, 40);
      } else {
        clearInterval(timer);
      }
      master.gain.setTargetAtTime(on ? 0.32 * duck : 0, ctx.currentTime, 0.6);
    }
    buttons.forEach((b) => {
      b.setAttribute("aria-pressed", String(on));
      b.classList.toggle("on", on);
      b.querySelector(".sound-label").textContent = t(on ? "soundOn" : "soundOff");
    });
  }
  buttons.forEach((b) => b.addEventListener("click", () => set(!on)));
  window.CS.onLang(() => buttons.forEach((b) => { b.querySelector(".sound-label").textContent = t(on ? "soundOn" : "soundOff"); }));

  // the explainer video lowers the music while its narrator speaks
  function setDuck(k) {
    duck = k;
    if (ctx && on) master.gain.setTargetAtTime(0.32 * duck, ctx.currentTime, 0.3);
  }

  // browsers only start audio after a gesture: restore a saved "on" at the first one
  const saved = on;
  set(false, false);
  if (saved) {
    const wake = () => { set(true); window.removeEventListener("pointerdown", wake); window.removeEventListener("keydown", wake); };
    window.addEventListener("pointerdown", wake);
    window.addEventListener("keydown", wake);
  }

  window.CSSound = { set, setDuck, get on() { return on; } };
})();
