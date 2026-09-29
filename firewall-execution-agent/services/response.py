import json
import azure.functions as func


def success(data=None):

    payload = {
        "status": "success"
    }
    if isinstance(data, dict):
        payload.update(data)
        payload.pop("xml", None)
        payload["status"] = "success"
    elif data not in (None, {}):
        payload["result"] = data

    return func.HttpResponse(
        json.dumps(payload),
        status_code=200,
        mimetype="application/json"
    )


def error(message, status_code=400):

    payload = {
        "status": "error",
        "message": message
    }

    return func.HttpResponse(
        json.dumps(payload),
        status_code=status_code,
        mimetype="application/json"
    )


def preview(message, data=None):

    payload = {
        "status": "preview",
        "message": message
    }
    if isinstance(data, dict):
        payload.update(data)
        payload.pop("xml", None)
        payload["status"] = "preview"
        payload["message"] = message

    return func.HttpResponse(
        json.dumps(payload),
        status_code=200,
        mimetype="application/json"
    )