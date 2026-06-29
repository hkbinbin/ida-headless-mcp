# Skills

Portable [Agent Skills](https://www.anthropic.com/news/skills) for working with
this project. Each subfolder is a self-contained skill: a `SKILL.md` (with YAML
frontmatter) plus any supporting files.

Drop a skill folder into your agent's skills directory (e.g.
`~/.codebuddy/skills/`, `~/.claude/skills/`, or `<project>/.workbuddy/skills/`)
and the agent will load it on demand.

## Available skills

| Skill | What it covers |
|-------|----------------|
| [`ida-cli`](ida-cli/SKILL.md) | Driving headless IDA Pro from the shell with `ida-cli` — open_session workflow, the ~60 dynamically generated subcommands, JSON argument passing, session management, and gotchas. |

> The `idapython` skill (modern IDAPython `ida_*` API reference) ships **inside
> the wheel** at `ida_pro_mcp/skills/idapython/` so that `use_help` can point at
> it after a plain `pip install`. The `ida-cli` skill here is also bundled in
> the wheel at `ida_pro_mcp/skills/ida-cli/`.

## Release artifact

Every tagged release attaches a `skills.zip` asset containing this folder, so
you can download the skills without cloning the repo. See the
[Releases page](https://github.com/hkbinbin/ida-headless-mcp/releases).
