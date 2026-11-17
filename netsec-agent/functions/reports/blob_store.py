import logging
import os
from datetime import datetime, timedelta, timezone

log = logging.getLogger("netsec-blob-store")


def publish_workbook(local_path, blob_name, expiry_hours=24):
    conn_str = (os.environ.get("AzureWebJobsStorage") or "").strip()
    if not conn_str or "UseDevelopmentStorage" in conn_str:
        return None
    if not local_path or not os.path.exists(local_path):
        return None
    try:
        from azure.storage.blob import (
            BlobSasPermissions,
            BlobServiceClient,
            ContentSettings,
            generate_blob_sas,
        )
    except Exception as exc:
        log.warning("azure-storage-blob not available: %s", exc)
        return None
    try:
        client = BlobServiceClient.from_connection_string(conn_str)
        container = "assessment-reports"
        container_client = client.get_container_client(container)
        try:
            container_client.create_container()
        except Exception:
            pass
        blob = container_client.get_blob_client(blob_name)
        with open(local_path, "rb") as handle:
            blob.upload_blob(
                handle,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type=(
                        "application/vnd.openxmlformats-officedocument"
                        ".spreadsheetml.sheet"
                    )
                ),
            )
        credential = getattr(client, "credential", None)
        account_key = getattr(credential, "account_key", None)
        if not account_key:
            return None
        sas = generate_blob_sas(
            account_name=client.account_name,
            container_name=container,
            blob_name=blob_name,
            account_key=account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
        )
        return "{0}?{1}".format(blob.url, sas)
    except Exception as exc:
        log.warning("blob publish failed: %s", exc)
        return None
