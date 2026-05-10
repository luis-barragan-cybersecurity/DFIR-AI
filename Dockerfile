# syntax=docker/dockerfile:1.6
# MemoryHound — Sub-Plan 05 production multi-stage build.
#
# Build:   docker buildx build --target runtime -t memoryhound:dev .
# Run:     docker run --rm -e ANTHROPIC_API_KEY=$KEY \
#              -v "$PWD/cases:/work/cases" memoryhound:dev orchestrate <case-id>
#
# The runtime image carries:
#   • orchestrator (mh-orchestrator)         — LangGraph IR state machine
#   • mcp-server   (protocol-sift-mcp)       — typed forensic primitives
#   • Volatility 3 + DFRWS 2008 ISF symbols  — vendored under corpus/
#   • Node 18 + @anthropic-ai/claude-code    — orchestrator shells out to it
#   • .claude/ skills + agents + hooks       — copied into MH_HOME
#   • non-root user hound:1000               — read-only image, writable /work
#
# Auth is ENV-driven (ANTHROPIC_API_KEY); no secrets are baked.

ARG PYTHON_VERSION=3.11
ARG MH_VERSION=sub-plan-05-complete

# ============================================================================
# Stage 1: builder — wheel cache for Python deps
# ----------------------------------------------------------------------------
# We pre-build wheels for the orchestrator + mcp-server[forensics] (volatility3,
# yara-python, etc.) here so the runtime stage can do a single `pip install
# --no-index --find-links /wheels` without dragging in build-essential.
# ============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Build deps for native wheels (yara-python, cryptography, python-magic
# cffi shims, etc.). These never ship in the runtime image.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        build-essential \
        libmagic-dev \
        libssl-dev \
        libffi-dev \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY mcp-server   /build/mcp-server
COPY orchestrator /build/orchestrator

RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip wheel --wheel-dir /wheels "./mcp-server[forensics]" \
    && pip wheel --wheel-dir /wheels  ./orchestrator

# ============================================================================
# Stage 2: runtime — lean target image
# ============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG MH_VERSION

# OCI labels — license expression covers Apache-2.0 (project) + MIT (Volatility
# Foundation symbols) + GPL-2.0-only (kernel-derived ISF data).
LABEL org.opencontainers.image.title="MemoryHound" \
      org.opencontainers.image.description="Autonomous DFIR triage built on Claude Code + LangGraph (SANS FIND EVIL! 2026)" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT AND GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/anthropics/memoryhound" \
      org.opencontainers.image.version="${MH_VERSION}"

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_NO_CACHE_DIR=1 \
    MH_HOME=/opt/memoryhound \
    MH_NO_CLAUDE=0 \
    DEBIAN_FRONTEND=noninteractive

# Runtime apt deps — strictly runtime; no compilers.
#
#   libmagic1   → python-magic file-type sniffing (mcp-server tools)
#   jq          → bin/mh + hooks shell out to jq
#   xz-utils    → Volatility 3 reads xz-compressed ISF JSON tables
#   curl, ca-*  → claude CLI install + general HTTPS
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        libmagic1 \
        jq \
        ca-certificates \
        curl \
        xz-utils \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# Node 18 + claude CLI — orchestrator's real-Claude path shells out to
# `claude --mcp-config ... --allowedTools ...`. The CLI is npm-installed
# globally so it lands on PATH at /usr/bin/claude.
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g @anthropic-ai/claude-code \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.npm

# ----------------------------------------------------------------------------
# Python venv at MH_HOME/.venv — bin/mh and bin/mh-mcp-server resolve the
# interpreter as ${MH_HOME}/.venv/bin/python; bin/mh further checks
# ${MH_VENV}/bin/mh-orchestrate. We honor that contract by installing the
# pre-built wheels (from the builder stage) directly into that venv.
# ----------------------------------------------------------------------------
COPY --from=builder /wheels /wheels
RUN python -m venv ${MH_HOME}/.venv \
    && ${MH_HOME}/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && ${MH_HOME}/.venv/bin/pip install --no-cache-dir --no-index --find-links /wheels \
        protocol-sift-mcp[forensics] \
        mh-orchestrator \
    && rm -rf /wheels /root/.cache

# Project files — launcher scripts, Claude skills/agents/hooks, vendored ISF.
# These live at canonical MH_HOME paths so the existing scripts find them
# without any path patching.
COPY bin/                                 ${MH_HOME}/bin/
COPY .claude/                             ${MH_HOME}/.claude/
COPY corpus/dfrws-2008-memory/symbols/    ${MH_HOME}/corpus/dfrws-2008-memory/symbols/

# Volatility 3 ISF symbol path — bin/mh-mcp-server already exports this when
# MH_HOME/corpus/.../symbols exists, but we set it here too so any direct
# `volatility3` invocation inside the container picks it up.
ENV VOLATILITY_SYMBOL_PATH=${MH_HOME}/corpus/dfrws-2008-memory/symbols

# Non-root user. UID 1000 matches the typical host user so bind-mounted
# cases/ stays writable without chown gymnastics.
#
# Principle of least privilege: ${MH_HOME} stays root:root (read-only to
# hound, world-readable for the venv + scripts + skills). hound only owns
# /work (writable workspace) and its home dir.
#
# `mh` hardcodes MH_CASES_DIR=${MH_HOME}/cases. We symlink that to
# /work/cases so users can bind-mount evidence at either path; both resolve
# to the same writable location.
RUN groupadd --gid 1000 hound \
    && useradd --uid 1000 --gid hound --shell /bin/bash --create-home hound \
    && mkdir -p /work/cases \
    && ln -s /work/cases ${MH_HOME}/cases \
    && chown -R hound:hound /work /home/hound

USER hound
WORKDIR /work
ENV PATH="${MH_HOME}/.venv/bin:${MH_HOME}/bin:${PATH}"

# `mh` is the single entrypoint; CMD is the default subcommand. Override at
# `docker run`: `docker run --rm memoryhound:dev orchestrate <case-id>`.
ENTRYPOINT ["/opt/memoryhound/bin/mh"]
CMD ["doctor"]
