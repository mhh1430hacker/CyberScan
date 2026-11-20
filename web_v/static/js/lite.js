/* Keep the landing page light: CSS animations run only in what the visitor can see.
 *
 * The page has ~80 decorative CSS animations (sheens, pulses, beams, demo strips). Left
 * alone they all run forever, including far off screen, and the ones that animate paint
 * properties make the browser restyle and repaint on every frame (measured: the main thread
 * was busy ~100% of the time at idle). Each top-level block of the landing gets .cs-off while
 * it is more than a little outside the viewport; theme.css pauses every animation inside it.
 * Transitions are untouched, so reveals still play as a block scrolls in. */
(function () {
  "use strict";
  const landing = document.getElementById("landing");
  if (!landing || !("IntersectionObserver" in window)) return;
  // the sections sit in <main> (the page's main landmark); the header and footer around it
  const blocks = landing.querySelectorAll(":scope > main > section, :scope > main > .bands, :scope > section, :scope > footer");
  const observer = new IntersectionObserver((entries) => {
    for (const e of entries) e.target.classList.toggle("cs-off", !e.isIntersecting);
  }, { rootMargin: "120px 0px 120px 0px" });
  blocks.forEach((b) => { b.classList.add("cs-off"); observer.observe(b); });

  // The whole page sleeps while the tab is in the background.
  document.addEventListener("visibilitychange", () => {
    document.documentElement.classList.toggle("cs-hidden", document.hidden);
  });
})();
