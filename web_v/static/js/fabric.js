/* Fabric: the choreography that ties the landing together (styles in fabric.css).
 *   - section headings and lead lines rise in a short stagger as their section arrives (.fx-rise → .fx-in);
 *   - once an entrance has finished, the element is marked .fx-done so hovers answer without the stagger delay.
 * One IntersectionObserver, no scroll handler, no rAF loop; nothing runs once everything has arrived.
 * Still (reduced motion): everything is shown at once. */
(function () {
  "use strict";
  const landing = document.getElementById("landing");
  if (!landing || !("IntersectionObserver" in window)) return;
  const html = document.documentElement;
  const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion");

  // the heading group of each section; the scroll stories and the hero have their own entrances
  const HEADS = ".sec-tag, .l-h2, .l-sub, .sci-sub, .sci-plain-intro, .stats-note, .tm-lead";
  const SKIP = ".hero, .sy, .sci-deep, .ks, [data-reveal], [data-tm-reveal]";

  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      e.target.classList.add("fx-in");
      io.unobserve(e.target);
    });
  }, { threshold: 0.2, rootMargin: "0px 0px -8% 0px" });

  function arm() {
    const calm = still();
    landing.querySelectorAll("main > section, main > .l-cta").forEach((sec) => {
      let i = 0;
      sec.querySelectorAll(HEADS).forEach((node) => {
        if (node.classList.contains("fx-rise") || node.closest(SKIP)) return;
        node.classList.add("fx-rise");
        node.style.setProperty("--fx-i", String(i++));
        if (calm) node.classList.add("fx-in", "fx-done"); else io.observe(node);
      });
    });
  }

  // when an entrance ends, drop its delay so hover and focus answer at once
  landing.addEventListener("transitionend", (e) => {
    const n = e.target;
    if (e.propertyName !== "opacity" || !n.classList) return;
    if ((n.classList.contains("in") && n.hasAttribute("data-reveal")) || n.classList.contains("fx-in")) n.classList.add("fx-done");
  });

  arm();
  // headings filled in later (a language change rebuilds some sections) are picked up too
  if (window.CS && typeof window.CS.onLang === "function") window.CS.onLang(arm);
})();
