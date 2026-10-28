# TRACE recorded demo — GitHub Pages

This branch contains the static deployment only. The fork preserves the upstream branches, including `webui` with the original UI and local live-run instructions.

The files in `ui/` are byte-for-byte copies of the published `web_ui/` assets at commit `c3b291e`. UI source code is unchanged. `boot.js` loads that UI in a full-page frame after the scoped service worker is ready. `static-demo-worker.js` maps the existing absolute asset/API paths to static files and returns `live_ready: false`. No Python server, Elasticsearch, credentials, or LLM calls are used.

The evidence is the retained synthetic SSH recording. Live controls are disabled. GitHub Pages serves this branch from its root. Service worker support and HTTPS are required (localhost also works for testing).
