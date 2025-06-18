from django import template

register = template.Library()


# This function is used to display the user votes.
# It returns a tuple with the rating value and a boolean indicating whether it is from the model or not (when not exist the user votes).
# This helps the HTML template display the votes in a different way.
@register.simple_tag
def get_vote(user_votes, model_votes, key):
    key = str(key)
    if key in user_votes:
        return user_votes[key], False
    if key in model_votes:
        return model_votes[key], True
    return None, False
