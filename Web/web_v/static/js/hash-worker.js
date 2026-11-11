/* SHA-256 of a dropped file, computed off the main thread with WebCrypto.
 * The file never leaves the browser for this step. */
self.onmessage = async (event) => {
  const { id, file } = event.data;
  try {
    const started = performance.now();
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    self.postMessage({ id, hex, ms: Math.round(performance.now() - started) });
  } catch (error) {
    self.postMessage({ id, error: String(error) });
  }
};
