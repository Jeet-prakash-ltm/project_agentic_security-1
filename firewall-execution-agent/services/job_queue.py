"""Azure Service Bus delivery for approved firewall jobs.

The queue is session-enabled so every job for a given firewall/device-group
is worked in order. PostgreSQL remains the source of truth for status; the
message only carries the task id and routing scope.
"""

import json
import logging
import os

logger = logging.getLogger("firewall.jobs.queue")

QUEUE_NAME = os.environ.get("FIREWALL_JOBS_QUEUE", "firewall-jobs")


def connection_string():
    return (os.environ.get("SERVICEBUS_CONNECTION") or "").strip()


def is_configured():
    return bool(connection_string())


def session_id_for(firewall_host, device_group):
    return "{0}/{1}".format(
        (firewall_host or "unknown").strip(),
        (device_group or "shared").strip(),
    )


def publish(job):
    """Send one job message. Returns the Service Bus message id."""
    if not is_configured():
        raise RuntimeError("SERVICEBUS_CONNECTION is not configured.")

    from azure.servicebus import ServiceBusClient, ServiceBusMessage

    payload = {
        "task_id": job["task_id"],
        "firewall_host": job.get("firewall_host") or "",
        "device_group": job.get("device_group") or "",
        "operation": job.get("operation") or "",
    }
    session_id = job.get("session_id") or session_id_for(
        job.get("firewall_host"), job.get("device_group")
    )

    with ServiceBusClient.from_connection_string(
        connection_string()
    ) as client:
        with client.get_queue_sender(QUEUE_NAME) as sender:
            sender.send_messages(
                ServiceBusMessage(
                    json.dumps(payload),
                    session_id=session_id,
                    message_id=str(job["task_id"]),
                    content_type="application/json",
                )
            )
    logger.info("Queued firewall job %s in session %s", job["task_id"], session_id)
    return str(job["task_id"])
