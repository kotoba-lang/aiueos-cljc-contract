# The `computer-virtual` backing as a fully host-isolated Linux container
# (aiueos ADR-0007). Xvfb gives a virtual framebuffer with NO host display, and
# Playwright drives a real Chromium on it with synthetic input — so the operator's
# keyboard/mouse/display never go active. This image IS the surface provider's
# backing; aiueos talks the computer-use ABI to `surface.mjs` over stdio.
#
#   docker build -t aiueos-computer-virtual examples/computer/backing
#   docker run --rm -i --init aiueos-computer-virtual < actions.jsonl
#
# Under OrbStack on macOS this runs as a normal Linux container — full host
# isolation (the container has no host HID to reach).
FROM mcr.microsoft.com/playwright:v1.59.0-jammy

# Xvfb is already needed by headed runs; headless Chromium needs none, but we keep
# the virtual framebuffer available so a fork can run headed inside the container.
ENV AIUEOS_PW=playwright \
    DISPLAY=:99 \
    AIUEOS_FRAME_DIR=/out
RUN mkdir -p /out

WORKDIR /srv
# The base image ships the browsers (/ms-playwright) but NOT the playwright npm
# package, so install it (pinned to the image's version) for `import("playwright")`.
RUN npm init -y >/dev/null 2>&1 && npm i --no-audit --no-fund playwright@1.59.0
COPY surface.mjs /srv/surface.mjs

# Playwright base image ships the browsers + node. Run the daemon on a virtual
# display: Xvfb :99 backs any headed work; the daemon itself launches headless.
ENTRYPOINT ["/bin/sh","-c","Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 & exec node /srv/surface.mjs"]
