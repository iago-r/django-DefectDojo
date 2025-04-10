import re

from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    return dictionary.get(str(key), None)


@register.filter
def extract_result_id(description):
    pattern = r"\*\*?ResultId\*\*?: ([a-f0-9\-]+)"
    match = re.search(pattern, description)

    if match:
        return match.group(1)
    return None
