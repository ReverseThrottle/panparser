# panparser

A PAN-OS XML configuration parser with two modes:

- **Viewer** — CLI and interactive TUI for reading and exploring any PAN-OS config export
- **Exporter** — structured JSON export for driving automated PAN-OS → SCM migrations via [scm-mcp](https://github.com/ReverseThrottle/scm-mcp)

---

## Requirements

- Python 3.10+

```bash
git clone https://github.com/ReverseThrottle/panparser.git
cd panparser
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Getting a Config Export from PAN-OS

**From the CLI:**
```bash
show config running    # compact — excludes defaults
show config all        # full — includes all inherited values
```

**From the GUI:** Device → Setup → Operations → Export Named Configuration Snapshot

Save the output as an XML file and pass it to panparser.

---

## Viewer Mode

### CLI

```bash
python3 -m panparser <config.xml> [options]

# Show all sections
python3 -m panparser running-config.xml

# Specific section(s)
python3 -m panparser running-config.xml -s security-rules
python3 -m panparser running-config.xml -s security-rules -s nat-rules

# Filter rows (case-insensitive substring match)
python3 -m panparser running-config.xml -s security-rules -g deny

# Target a different vsys; skip shared objects
python3 -m panparser running-config.xml --vsys vsys2 --no-shared

# No color (for piping)
python3 -m panparser running-config.xml --no-color | less
```

**Available sections:**
`addresses`, `address-groups`, `services`, `service-groups`, `security-rules`, `nat-rules`,
`zones`, `interfaces`, `routing`, `tags`, `profiles`, `applications`, `app-groups`,
`app-filters`, `dos-rules`

### TUI

```bash
python3 -m panparser <config.xml> --tui [options]

python3 -m panparser running-config.xml --tui
python3 -m panparser running-config.xml --tui --vsys vsys2
```

| Key | Action |
|-----|--------|
| `/` | Focus filter bar |
| `r` | Clear filter |
| `Esc` | Return focus to table |
| `↑` / `↓` | Navigate rows |
| `Tab` / click | Switch sections |
| `q` | Quit |

### What the viewer covers

| Section | CLI | TUI |
|---------|:---:|:---:|
| Address objects | ✓ | ✓ |
| Address groups (tree) | ✓ | ✓ |
| Service objects | ✓ | ✓ |
| Service groups (tree) | ✓ | ✓ |
| Security policy rules | ✓ | ✓ |
| NAT rules | ✓ | ✓ |
| Security zones | ✓ | ✓ |
| Network interfaces + subinterfaces | ✓ | ✓ |
| Static routes (per virtual router) | ✓ | ✓ |
| Tags | ✓ | ✓ |
| Security profiles | ✓ | ✓ |
| Custom applications | ✓ | ✓ |
| Application groups + filters | ✓ | ✓ |
| DoS protection rules | ✓ | — |

---

## Exporter Mode

Produces a structured JSON file shaped to match the scm-mcp migration pipeline. All objects are
extracted in a dependency-aware structure — scm-mcp reads the file and pushes everything into SCM
in the correct order.

```bash
python3 -m panparser <config.xml> --output <export.json>

# Force overwrite an existing file
python3 -m panparser running-config.xml --output ~/exports/fw1.json --force

# Target a non-default vsys
python3 -m panparser running-config.xml --output ~/exports/fw1.json --vsys vsys2
```

The exporter prints a summary to stderr on completion:

```
Exported to ~/exports/fw1.json  [fw1  PAN-OS 10.2.0]
  network : 5 virtual_router(s)  5 ike_crypto  6 ipsec_crypto  2 ike_gw  1 ipsec_tunnel ...
  objects : 62 tags  755 addresses  143 addr_groups  ...
  profiles: 0 anti_spyware  ...  1 dos_prot  2 dos_rules
  30 migration warning(s) — review 'migration_warnings' in the output
```

### Export JSON structure

```
{
  "meta": { hostname, sw_version, vsys, source_file, exported_at },
  "objects": {
    "tags", "addresses", "stub_objects", "address_groups",
    "services", "service_groups", "application_groups", "url_categories",
    "profile_groups", "syslog_server_profiles", "http_server_profiles",
    "log_forwarding_profiles", "authentication_profiles",
    "radius_server_profiles", "ldap_server_profiles", "kerberos_server_profiles",
    "saml_server_profiles", "tacacs_server_profiles",
    "schedules", "edls", "custom_applications", "application_filters"
  },
  "policy": {
    "security_rules", "nat_rules", "decryption_rules",
    "authentication_rules", "pbf_rules", "qos_rules", "dos_protection_rules"
  },
  "zones": [ ... ],
  "security_profiles": {
    "anti_spyware", "wildfire_antivirus", "vulnerability_protection",
    "url_access", "decryption", "dns_security", "file_blocking",
    "zone_protection", "dos_protection"
  },
  "network": {
    "virtual_routers": [ ... ],   // includes BGP, OSPF, static routes, redistribution
    "ike_crypto_profiles", "ipsec_crypto_profiles",
    "ike_gateways", "ipsec_tunnels",
    "interfaces": { ethernet, ethernet_subinterfaces, loopback, tunnel, aggregate, aggregate_subinterfaces },
    "interface_management_profiles"
  },
  "migration_warnings": [ { severity, object_path, message } ]
}
```

### Using the export with scm-mcp

In Claude Code with scm-mcp connected:

```
Migrate the panparser export at ~/exports/fw1.json into the Production folder.
Do a dry run first so I can review what will be created.
```

Or call the tool directly:

```
scm_migrate_panparser_export(
    export_path="~/exports/fw1.json",
    folder="Production",
    dry_run=True
)
```

---

## Known Limitations

These are tracked as open GitHub issues.

### IKE Gateway Pre-Shared Keys

PAN-OS encrypts PSKs in the XML config — they cannot be recovered. Every IKE gateway using
pre-shared key authentication is exported with the placeholder `MIGRATION-PLACEHOLDER-PSK`.
The gateway pushes successfully but the tunnel will not come up until the real PSK is set manually
in SCM after migration. Gateways using certificate authentication are not affected.

Tracked in [scm-mcp#12](https://github.com/ReverseThrottle/scm-mcp/issues/12).

### IPSec Tunnel-Interface Binding ([#2](https://github.com/ReverseThrottle/panparser/issues/2))

The `tunnel_interface` field (e.g. `tunnel.1`) is not included in the IPSec tunnel export.
The SCM REST API accepts it but the field was omitted while the SDK did not support it.
After migration, bind each tunnel to its interface manually via `scm_update_ipsec_tunnel`
or in the SCM UI.

The fix is straightforward — extract `<tunnel-interface>` in `export_ipsec_tunnels()` and the
scm-mcp migration pipeline will pass it through automatically ([scm-mcp#13](https://github.com/ReverseThrottle/scm-mcp/issues/13)).

### DoS Profile Flood Rates for Disabled Protocols

SCM enforces rate constraints (`alarm-rate` / `activate-rate` / `maximal-rate`) on flood
protocol entries even when `enable: false`. Protocols with `enable: false` are reduced to
`{"enable": false}` before pushing — their rate settings are not migrated. If a disabled
protocol had non-default rates configured, those will need to be set manually once
re-enabled in SCM.

---

## Project Layout

```
panparser/
├── export/
│   ├── objects.py        # All per-section export functions
│   └── writer.py         # Assembles full export dict, writes JSON, prints summary
├── parsers/
│   ├── _helpers.py       # Shared XML utilities (get_members, iter_entries, etc.)
│   ├── addresses.py
│   ├── applications.py
│   ├── dos.py
│   ├── interfaces.py
│   ├── nat.py
│   ├── profiles.py
│   ├── routing.py
│   ├── security.py
│   ├── services.py
│   ├── tags.py
│   └── zones.py
├── pyproject.toml
└── README.md
```

---

## Notes

- The viewer is **read-only** — it never connects to a firewall or modifies any files.
- Tested against PAN-OS 10.x and 11.x config exports.
- Multi-vsys firewalls: use `--vsys` to target a specific vsys (default: `vsys1`).
- Both vsys-scoped and `<shared>`-scoped objects are parsed by default (`--no-shared` to skip shared).
