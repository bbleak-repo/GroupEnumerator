# Group Enumerator — Playbook

The **Markdown here is the source of truth.** HTML for end users is generated from it.

## Files
| File | Audience | Contents |
|---|---|---|
| `00-foundations.md` | both | install, auth + tiers, full config reference, environments, the safety/what-if model, output/report locations, glossary |
| `cli-playbook.md` | operators / automation | every entry script + every parameter, reports catalog, recipes, troubleshooting |
| `gui-playbook.md` | analysts / reviewers | every tab + control, presets, task recipes |

## HTML build (two guides, each concept written once)
- **CLI guide** = `00-foundations.md` + `cli-playbook.md`
- **GUI guide** = `00-foundations.md` + `gui-playbook.md`

Foundations is shared, so install/auth/config/safety are authored **once** and never
duplicated across the two guides — the same anti-drift principle the project follows for
code. To produce HTML, concatenate the two files for each guide and run any Markdown→HTML
converter (e.g. `pandoc foundations.md cli-playbook.md -o cli-guide.html --toc`), or wire a
small build step later.

## Maintenance rule
When a CLI flag or GUI control changes: update it in the **one** place that owns its
semantics (a flag in `cli-playbook.md`; a control row in `gui-playbook.md` pointing to the
flag). Don't restate a flag's meaning in the GUI doc — link to it. Keep `00-foundations.md`
as the only home for shared setup/safety/config.
