# axupdate + axreports release guide

This repository is now organized as a deployment-ready split:

- `axupdate.py` is the desktop GUI application.
- `axreports.py` is the stable host-source-aware report/monitoring tool.
- `repo_sources.json` is the repo/channel metadata file used for report link mapping.
- GitHub Pages is the static download/report publication surface.

## Stable runtime

Run the report tool with:

```bash
python3 axreports.py --json
python3 axreports.py --repo-config repo_sources.json --json
python3 axreports.py --apply
```

## Export a report file

```bash
python3 axreports.py --json --output reports/latest.json
```

## Host package source locations

The real update/release sources for the host should remain under:

- `/etc/apt/sources.list`
- `/etc/apt/sources.list.d/*.list`
- `/etc/apt/sources.list.d/*.sources`

These are the source-of-truth locations for:

- kernel updates
- application updates
- OS upgrade channels
- security and backports channels

## GitHub Pages role

GitHub Pages should be used for:

- release/download pages
- HTML report snapshots
- JSON artifact publishing
- stable public report feed

GitHub Pages is not the runtime source for the actual host package manager.
