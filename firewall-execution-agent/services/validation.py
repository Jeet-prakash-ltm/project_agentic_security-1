class ValidationError(Exception):
    pass


def require_xpath(body):

    xpath = body.get("xpath")

    if not xpath:
        raise ValidationError(
            "xpath is required"
        )

    return xpath


def require_element(body):

    element = body.get("element")

    if not element:
        raise ValidationError(
            "element is required"
        )

    return element


def require_cmd(body):

    cmd = body.get("cmd")

    if not cmd:
        raise ValidationError(
            "cmd is required"
        )

    return cmd