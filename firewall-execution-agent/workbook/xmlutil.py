def xml_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def entry_xml(name, inner=None):
    return '<entry name="{0}">{1}</entry>'.format(xml_escape(name), inner or "")


def member_list_xml(tag, values):
    items = []
    for value in values or []:
        value = str(value).strip()
        if value:
            items.append("<member>{0}</member>".format(xml_escape(value)))
    if not items:
        return ""
    return "<{0}>{1}</{0}>".format(xml_escape(tag), "".join(items))
