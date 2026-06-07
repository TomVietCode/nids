"""
Config management API — read, update, and reset config.py values.

  GET    /api/config         → JSON list of editable config variables
  POST   /api/config         → update config.py with new values
  POST   /api/config/reset   → restore factory defaults

Uses Python's ast module to safely parse config.py without eval().
Excludes the Logging / persistence section from editing.
"""

import ast
import importlib
import re
import textwrap
from pathlib import Path

from flask import Blueprint, jsonify, request

import config

config_bp = Blueprint("config", __name__, url_prefix="/api/config")

# Absolute path to config.py, resolved relative to this file's parent
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.py"

# Variables in the "Logging / persistence" section — never exposed to the UI
_EXCLUDED_VARS = {
    "DB_PATH",
    "BULK_INSERT_BATCH_SIZE",
    "FLUSH_INTERVAL_SEC",
    "ALERT_COOLDOWN_SEC",
}

# Factory defaults for the "Reset to Defaults" feature.
# Must be kept in sync if config.py defaults change.
_DEFAULTS = {
    "NETWORK_INTERFACE": "ens33",
    "VPS_IP": "192.168.68.128",
    "VMWARE_GATEWAY_IP": "192.168.68.2",
    "VMWARE_HOST_IP": "192.168.68.1",
    "FLASK_HOST": "0.0.0.0",
    "FLASK_PORT": 5000,
    "PORT_SCAN_THRESHOLD": 15,
    "PORT_SCAN_WINDOW_SEC": 5,
    "BRUTE_FORCE_THRESHOLD": 20,
    "BRUTE_FORCE_WINDOW_SEC": 10,
    "BRUTE_FORCE_PORTS": [22, 21],
    "FLOOD_PACKET_RATE_THRESHOLD": 500,
    "PING_SWEEP_HOST_THRESHOLD": 10,
    "PING_SWEEP_WINDOW_SEC": 5,
    "AUTO_BLOCK_SEVERITIES": ["HIGH", "CRITICAL"],
    "RATE_LIMIT_SEVERITIES": ["MEDIUM"],
    "RATE_LIMIT_RULE": "10/min",
    "FILTER_ARP_BROADCASTS": True,
    "FILTER_PROTOCOLS": ["ARP"],
    "TRUSTED_LOCAL_SUBNETS": ["192.168.68.0/24"],
    "GATEWAY_IPS": ["192.168.68.1", "192.168.68.2"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_sections() -> list[dict]:
    """Parse config.py using ast to extract variable names, values, and sections.

    Returns a list of dicts:
      {"name": str, "value": any, "type": str, "section": str, "comment": str}
    """
    source = _CONFIG_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Build a line→section mapping from comment headers
    section_map = {}
    current_section = "General"
    for line_no, line in enumerate(source.splitlines(), start=1):
        # Match section headers like: # DET-01 Port Scan
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("# ---"):
            # Check if the previous or next line is a separator
            lines = source.splitlines()
            idx = line_no - 1  # 0-indexed
            is_header = False
            if idx > 0 and lines[idx - 1].strip().startswith("# ---"):
                is_header = True
            if idx + 1 < len(lines) and lines[idx + 1].strip().startswith("# ---"):
                is_header = True
            if is_header:
                current_section = stripped.lstrip("# ").strip()
        section_map[line_no] = current_section

    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            # Skip private/dunder names and excluded vars
            if name.startswith("_") or name in _EXCLUDED_VARS:
                continue
            # Skip computed expressions (IGNORE_IPS, IGNORE_DST_IPS use set
            # comprehensions / f-strings that can't be safely round-tripped)
            if name in ("IGNORE_IPS", "IGNORE_DST_IPS", "IGNORE_UDP_PORTS"):
                continue

            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                # Not a literal (e.g., references another variable) — skip
                continue

            py_type = type(value).__name__
            section = section_map.get(node.lineno, "General")

            # Grab inline comment if any
            comment = ""
            line_text = source.splitlines()[node.lineno - 1]
            match = re.search(r"#\s*(.+)$", line_text)
            if match:
                comment = match.group(1).strip()

            results.append({
                "name": name,
                "value": value,
                "type": py_type,
                "section": section,
                "comment": comment,
            })

    return results


def _coerce_value(name: str, raw_value, expected_type: str):
    """Coerce a JSON-submitted value to the correct Python type.

    Returns (coerced_value, error_string_or_None).
    """
    try:
        if expected_type == "int":
            v = int(raw_value)
            if v < 0:
                return None, f"{name}: must be non-negative"
            return v, None
        elif expected_type == "float":
            return float(raw_value), None
        elif expected_type == "bool":
            if isinstance(raw_value, bool):
                return raw_value, None
            if isinstance(raw_value, str):
                return raw_value.lower() in ("true", "1", "yes"), None
            return bool(raw_value), None
        elif expected_type == "str":
            return str(raw_value), None
        elif expected_type == "list":
            if isinstance(raw_value, list):
                return raw_value, None
            # Accept comma-separated string
            if isinstance(raw_value, str):
                items = [s.strip() for s in raw_value.split(",") if s.strip()]
                return items, None
            return None, f"{name}: expected a list"
        elif expected_type == "set":
            if isinstance(raw_value, (list, set)):
                return set(raw_value), None
            return None, f"{name}: expected a list/set"
        else:
            return raw_value, None
    except (ValueError, TypeError) as e:
        return None, f"{name}: {e}"


def _rewrite_config(updates: dict[str, object]) -> None:
    """Rewrite config.py, replacing only the values of specified variables.

    Preserves all comments, blank lines, and structure.
    """
    source = _CONFIG_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)

    # Collect (line_index, col_offset, old_text_len, new_repr) replacements.
    # Process bottom-up so line offsets don't shift.
    replacements = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in updates:
                val = updates[target.id]
                new_repr = repr(val)
                # The value node's position in the source
                value_node = node.value
                start_line = value_node.lineno - 1  # 0-indexed
                start_col = value_node.col_offset
                end_line = value_node.end_lineno - 1
                end_col = value_node.end_col_offset

                replacements.append(
                    (start_line, start_col, end_line, end_col, new_repr)
                )

    # Sort bottom-up, right-to-left so replacements don't invalidate indices
    replacements.sort(key=lambda r: (r[0], r[1]), reverse=True)

    for start_line, start_col, end_line, end_col, new_repr in replacements:
        if start_line == end_line:
            # Single-line replacement
            line = lines[start_line]
            lines[start_line] = line[:start_col] + new_repr + line[end_col:]
        else:
            # Multi-line: replace from start to end
            first = lines[start_line]
            last = lines[end_line]
            lines[start_line] = first[:start_col] + new_repr + last[end_col:]
            del lines[start_line + 1 : end_line + 1]

    _CONFIG_PATH.write_text("".join(lines), encoding="utf-8")

    # Reload the config module so the running process picks up changes
    importlib.reload(config)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@config_bp.get("")
def get_config():
    """Return all editable config variables grouped by section."""
    items = _parse_sections()
    # Group by section for the UI
    grouped: dict[str, list] = {}
    for item in items:
        grouped.setdefault(item["section"], []).append(item)
    return jsonify({"sections": grouped})


@config_bp.post("")
def update_config():
    """Update config.py with submitted values.

    Expects JSON body: {"values": {"VAR_NAME": new_value, ...}}
    """
    body = request.get_json(force=True, silent=True) or {}
    new_values = body.get("values", {})
    if not new_values:
        return jsonify({"error": "No values provided"}), 400

    # Get current config for type validation
    current = {item["name"]: item for item in _parse_sections()}

    errors = []
    coerced = {}
    for name, raw in new_values.items():
        if name in _EXCLUDED_VARS:
            errors.append(f"{name}: cannot modify logging/persistence settings")
            continue
        if name not in current:
            errors.append(f"{name}: unknown config variable")
            continue

        expected_type = current[name]["type"]
        val, err = _coerce_value(name, raw, expected_type)
        if err:
            errors.append(err)
        else:
            coerced[name] = val

    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    try:
        _rewrite_config(coerced)
    except Exception as e:
        return jsonify({"error": f"Failed to write config: {e}"}), 500

    return jsonify({"ok": True, "updated": list(coerced.keys())})


@config_bp.post("/reset")
def reset_config():
    """Restore all editable variables to factory defaults."""
    try:
        _rewrite_config(_DEFAULTS)
    except Exception as e:
        return jsonify({"error": f"Failed to reset config: {e}"}), 500
    return jsonify({"ok": True, "message": "All settings restored to defaults"})
