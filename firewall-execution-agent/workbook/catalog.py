"""Playbook catalogue driving the NetSec Execution Agent.

Playbook definitions live as YAML files under ``netsec_execution/playbooks``
(one file per playbook, matching the playbook ``id``). Each file declares the
workbook sheet it maps to, its template columns, example rows, column widths
and a ``services`` handler reference that executes each row.

This module loads the YAML catalogue once at import time and exposes the same
public API the engine and web service depend on (``PLAYBOOKS``,
``CATEGORIES``, ``list_playbooks`` and ``find_playbook``).
"""

from workbook import loader

PLAYBOOKS = loader.load_playbooks()

CATEGORIES = loader.categories(PLAYBOOKS)


def list_playbooks():
    """Public catalogue payload for the workspace playbook panel."""
    result = []
    for playbook in PLAYBOOKS:
        examples = playbook.get("examples") or [{}]
        result.append(
            {
                "id": playbook["id"],
                "title": playbook["title"],
                "category": playbook["category"],
                "sheet": playbook["sheet"],
                "summary": playbook["summary"],
                "columns": list(playbook.get("columns") or []),
                "example": dict(examples[0]) if examples else {},
            }
        )
    return result


def find_playbook(playbook_id):
    for playbook in PLAYBOOKS:
        if playbook["id"] == playbook_id:
            return playbook
    return None
