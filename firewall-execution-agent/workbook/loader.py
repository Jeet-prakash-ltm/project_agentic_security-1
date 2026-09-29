"""YAML playbook loader.

Playbook definitions are plain YAML files stored under the package
``playbooks`` directory (one file per playbook). Each file declares the
workbook sheet it maps to, its template columns, example rows and column
widths, plus a dotted ``handler`` reference to the ``services`` function that
executes a single row::

    handler: services.objects.apply_addresses

``load_playbooks`` reads every ``*.yaml`` file in the directory, validates the
required keys and resolves each handler (lazily importing the module) so the
returned playbooks are directly usable by the engine exactly like the
hand-written catalogue they replace.
"""

import importlib
import logging
import os

import yaml

logger = logging.getLogger("netsec.loader")

_PACKAGE = __name__.split(".")[0]
_PLAYBOOKS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "playbooks"
)

_REQUIRED = ("id", "title", "category", "sheet", "summary", "handler", "columns")


def _resolve_handler(reference):
    if not isinstance(reference, str) or "." not in reference:
        raise ValueError(
            "playbook handler {0!r} must be a dotted reference".format(reference)
        )
    if reference.startswith("services."):
        module_path = "workbook." + reference[len("services."):]
    elif reference.startswith("workbook."):
        module_path = reference
    else:
        module_path = "workbook." + reference
    module_name, _, function_name = module_path.rpartition(".")
    module = importlib.import_module(module_name)
    handler = getattr(module, function_name, None)
    if not callable(handler):
        raise ValueError(
            "playbook handler {0!r} does not resolve to a callable".format(reference)
        )
    return handler


def load_playbooks(directory=None):
    """Load and resolve every YAML playbook, returning a list of dicts.

    Files are processed in filename order so the resulting catalogue order is
    deterministic. A duplicate ``id`` or a missing required key raises
    ``ValueError`` so configuration mistakes fail loudly at import time.
    """
    directory = directory or _PLAYBOOKS_DIR
    filenames = sorted(
        name for name in os.listdir(directory) if name.endswith(".yaml")
    )
    if not filenames:
        logger.warning("No playbook YAML files found under %s", directory)
    seen = set()
    playbooks = []
    for filename in filenames:
        path = os.path.join(directory, filename)
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError("playbook {0} is not a YAML mapping".format(filename))
        missing = [key for key in _REQUIRED if not data.get(key)]
        if missing:
            raise ValueError(
                "playbook {0} is missing required key(s): {1}".format(
                    filename, ", ".join(missing)
                )
            )
        playbook_id = data["id"]
        if playbook_id in seen:
            raise ValueError(
                "duplicate playbook id {0} in {1}".format(playbook_id, filename)
            )
        seen.add(playbook_id)
        playbooks.append(
            {
                "id": playbook_id,
                "title": data["title"],
                "category": data["category"],
                "sheet": data["sheet"],
                "summary": data["summary"],
                "columns": list(data["columns"]),
                "examples": list(data.get("examples") or []),
                "column_widths": dict(data.get("column_widths") or {}),
                "apply": _resolve_handler(data["handler"]),
            }
        )
    return playbooks


def categories(playbooks):
    """Ordered unique category labels for a loaded playbook list."""
    result = []
    for playbook in playbooks:
        category = playbook.get("category")
        if category and category not in result:
            result.append(category)
    return result
