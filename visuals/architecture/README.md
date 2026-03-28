# Architecture Assets

This directory contains the technical architecture report plus the optional supporting visuals for the `pip-guard` flow.

## Primary Artifact

- [pip-guard-architecture-report.html](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-report.html)
  A short technical report covering runtime boundaries, evidence flow, interfaces, and decision semantics.

## Scenes

- `PipGuardArchitectureAnimation`
  Optional animated walkthrough showing:
  - local `pip-guard install ...`
  - handoff into the Daytona sandbox
  - staged package analysis and parallel tool stack
  - Codex as the reasoning layer
  - Rich summary + HTML report + install gate
  - sandbox clear-down / idle state

- `PipGuardArchitecturePoster`
  A static poster frame built from the same layout.

## Render

Install the visual toolchain first:

```sh
uv sync --extra visuals
```

Render the main animation:

```sh
./visuals/architecture/render.sh PipGuardArchitectureAnimation h
```

Render a faster preview:

```sh
./visuals/architecture/render.sh PipGuardArchitectureAnimation l
```

Render the poster scene:

```sh
./visuals/architecture/render.sh PipGuardArchitecturePoster h
```

## Presentation Tuning

The visual stack is intentionally data-driven at the top of [pip_guard_architecture.py](/Users/ivogarais/pip-guard-/visuals/architecture/pip_guard_architecture.py):

- `TOOL_STACK`
  Change the visible tools and accent colors.

- `PipGuardArchitectureAnimation`
  Adjust the wording of the captions and the cleanup language.

That makes it easy to keep the choreography while changing the slide language for demos, product pitches, or investor presentations.

## Output Assets

Rendered deliverables are stored in:

- [pip-guard-architecture-report.html](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-report.html)
- [pip-guard-architecture-1080p60.mp4](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-1080p60.mp4)
- [pip-guard-architecture-preview-480p15.mp4](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-preview-480p15.mp4)
- [pip-guard-architecture-poster.png](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-poster.png)

The HTML report is the primary documentation artifact. The poster and videos are optional visual companions and are not required to understand the technical design.
