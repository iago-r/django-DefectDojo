from django import template

register = template.Library()


@register.simple_tag
def get_vote(user_votes, model_votes, key):
    key = str(key)
    if key in user_votes:
        return user_votes[key], False
    elif key in model_votes:
        return model_votes[key], True
    return None, False
