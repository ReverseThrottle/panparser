# panparser

A read-only PAN-OS XML configuration parser and viewer. Parses `show config running` or `show config all` exports from Palo Alto Networks firewalls and presents every major section in a clean, human-readable format.

Two interfaces:
- **CLI** — one-shot output with `rich`-rendered tables and trees, pipeable to `less`
- **TUI** — interactive Textual app with live filtering, tab navigation, and a row detail panel

---

## Features

Parses and displays:

| Section | CLI | TUI |
|---------|-----|-----|
| Address objects | ✓ | ✓ |
| Address groups | ✓ (tree) | ✓ |
| Service objects | ✓ | ✓ |
| Service groups | ✓ (tree) | ✓ |
| Security policy rules | ✓ | ✓ |
| NAT rules | ✓ | ✓ |
| Security zones | ✓ | ✓ |
| Network interfaces + subinterfaces | ✓ | ✓ |
| Static routes (per virtual router) | ✓ | ✓ |
| Tags | ✓ | ✓ |
| Security profiles (AV, IPS, URL, WildFire, File-blocking) | ✓ | ✓ |
| Custom applications | ✓ | ✓ |
| Application groups | ✓ | ✓ |
| Application filters | ✓ | ✓ |

- Parses both **vsys-scoped** and **`<shared>`-scoped** objects
- Handles both `show config running` and `show config all` (full config with defaults) export formats
- Color-coded security rule actions (allow=green, deny=red, reset=yellow)
- Disabled rules rendered dimmed

---

## Requirements

- Python 3.10+
- [`rich`](https://github.com/Textualize/rich) — CLI rendering
- [`textual`](https://github.com/Textualize/textual) — TUI

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Exporting the config from PAN-OS

From the CLI:
```bash
# Running config (compact, excludes defaults)
show config running

# Full config (includes all defaults and inherited values)
show config all
```

From the GUI: **Device → Setup → Operations → Export Named Configuration Snapshot**

Save the output as an XML file and pass it to panparser.

---

### CLI

```bash
python panparser.py <config.xml> [options]

# Show everything
python panparser.py running-config.xml

# Specific section(s)
python panparser.py running-config.xml -s security-rules
python panparser.py running-config.xml -s security-rules -s nat-rules

# Filter rows (case-insensitive substring match)
python panparser.py running-config.xml -s security-rules -g deny

# Target a different vsys; skip shared objects
python panparser.py running-config.xml --vsys vsys2 --no-shared

# No color (for piping)
python panparser.py running-config.xml --no-color | less
```

**Available sections:**
`addresses`, `address-groups`, `services`, `service-groups`, `security-rules`, `nat-rules`, `zones`, `interfaces`, `routing`, `tags`, `profiles`, `applications`, `app-groups`, `app-filters`

---

### TUI

```bash
python tui.py <config.xml> [options]

python tui.py running-config.xml
python tui.py running-config.xml --vsys vsys2 --no-shared
```

**Keybindings:**

| Key | Action |
|-----|--------|
| `/` | Focus filter bar — type to live-filter the current tab |
| `r` | Reset/clear the filter |
| `Esc` | Return focus to the table |
| `↑` / `↓` | Navigate rows; detail bar at the bottom shows full values |
| `Tab` / click | Switch sections |
| `q` | Quit |

---

## Project Layout

```
panparser/
├── panparser.py          # CLI entry point
├── tui.py                # Textual TUI entry point
├── requirements.txt
└── parsers/
    ├── _helpers.py       # Shared XML utilities
    ├── _data.py          # Pure data extraction (used by TUI)
    ├── addresses.py
    ├── services.py
    ├── security.py
    ├── nat.py
    ├── zones.py
    ├── interfaces.py
    ├── routing.py
    ├── tags.py
    ├── profiles.py
    └── applications.py
```

The `parsers/_data.py` module is the data-only extraction layer — no rendering, returns plain Python tuples. The CLI parsers use `rich` directly; the TUI imports from `_data.py` and populates `textual` `DataTable` widgets.

---

## Notes

- This tool is **read-only** — it never connects to a firewall or modifies any files.
- Tested against PAN-OS 10.x and 11.x config exports.
- Multi-vsys firewalls: use `--vsys` to target a specific vsys (default: `vsys1`).
