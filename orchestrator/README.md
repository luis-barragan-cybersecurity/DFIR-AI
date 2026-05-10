# mh-orchestrator

LangGraph state-machine orchestrator for MemoryHound. Wraps the Claude Code
subagents defined in `.claude/agents/` as graph-executable nodes.

See `Plans/plan-02-first-zany-kurzweil.md` (the sub-plan) and
`Plans/IR_FRAMEWORKS_REFERENCE.md` §11 for design.

## Install (editable)

    pip install -e ./orchestrator

## Run

    mh-orchestrate run case-001
