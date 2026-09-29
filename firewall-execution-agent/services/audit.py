import logging

logger = logging.getLogger("firewall_execution")


def audit(
        operation,
        description=None,
        xpath=None,
        result=None):

    logger.info(
        "operation=%s xpath=%s description=%s result=%s",
        operation,
        xpath,
        description,
        result
    )