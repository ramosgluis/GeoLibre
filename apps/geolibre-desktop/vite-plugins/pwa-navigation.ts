/**
 * Server-owned paths the PWA must never replace with the GeoLibre app shell.
 *
 * Share serves its own HTML, API, and project JSON under `/share`. Keeping the
 * whole namespace here is essential: an installed service worker sees browser
 * navigations before nginx/FastAPI and would otherwise answer them with the
 * precached `index.html`.
 */
export const SPA_NAVIGATION_DENYLIST = [
  /^\/sidecar\//,
  /^\/share(?:\/|$)/,
  /^\/__geolibre_/,
  /\/[^/?]+\.[^/]+$/,
];
