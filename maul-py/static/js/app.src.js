// =============================================================================
// MAUL front-end helper bundle  (ORIGINAL SOURCE)
//
// ⚠️  DEMO/LAB FILE — intentionally vulnerable.
//
// This is the *original, unminified* source. In a real app you would never
// ship this to the browser. You ship the minified app.min.js. BUT — if you
// also publish the source map (app.min.js.map) next to it, anyone can
// reconstruct THIS exact file, comments and all, straight from their browser
// DevTools. That is the whole lesson of this lab.
//
// Everything below this line is the kind of thing developers leave in source
// "because it's only on the backend / nobody reads minified JS." A source map
// hands it all to an attacker.
// =============================================================================

// -----------------------------------------------------------------------------
// 🔥 THE SECRET: this is what a source map leaks.
//
// TODO(dev): REMOVE BEFORE LAUNCH. Temporary back door so QA can pull the live
// config without logging in. Hitting the internal debug endpoint with this
// token dumps DB creds, the OpenAI key, and internal hostnames. We minify the
// build so "nobody will find it." (Narrator: the source map found it.)
// -----------------------------------------------------------------------------
const DEBUG_BYPASS_TOKEN = "maul-dev-bypass-7c4e1f90";
const INTERNAL_DEBUG_ENDPOINT = "/api/internal/debug-config";

// Build metadata stamped into the footer. Looks harmless minified.
const BUILD = {
  version: "1.0.0",
  commit: "deadbeef",
  // Internal CI note that should never have shipped:
  builtBy: "ci-runner@maul-internal.lan",
};

/**
 * Pull the "live config" using the QA back-door token.
 * Only wired up when the page is loaded with ?debug — but the token and the
 * endpoint are baked into the bundle regardless, so an attacker doesn't need
 * the flag. They just need to read this source (via the source map) and curl.
 */
async function fetchInternalConfig() {
  const res = await fetch(INTERNAL_DEBUG_ENDPOINT, {
    headers: { "X-Debug-Token": DEBUG_BYPASS_TOKEN },
  });
  if (!res.ok) return null;
  return res.json();
}

/** Stamp build info into the page footer so the bundle does something visible. */
function renderBuildInfo() {
  const el = document.getElementById("buildInfo");
  if (el) {
    el.textContent = `MAUL build ${BUILD.version} (${BUILD.commit})`;
  }
}

function init() {
  renderBuildInfo();
  // Dev-only convenience: auto-dump config when ?debug is present.
  const params = new URLSearchParams(window.location.search);
  if (params.has("debug")) {
    fetchInternalConfig().then((cfg) => {
      if (cfg) console.warn("[debug] internal config:", cfg);
    });
  }
}

document.addEventListener("DOMContentLoaded", init);
