from datetime import timedelta

import panther_event_type_helpers as event_type
from panther_oss_helpers import put_string_set, resolve_timestamp_string

# Days an account is considered new
TTL = timedelta(days=3)


def rule(event):
    if event.udm("event_type") != event_type.ACCOUNT_CREATED:
        return False

    user_event_id = f"new_user_{event.get('p_row_id')}"
    account_event_id = f"new_account_{event.get('p_row_id')}"
    new_user = event.udm("user")
    new_account = event.udm("account_id")
    event_time = resolve_timestamp_string(event.get("p_event_time"))
    expiry_time = event_time + TTL

    if new_user:
        put_string_set(new_user, [user_event_id], expiry_time.strftime("%s"))
    if new_account:
        put_string_set(new_account, [account_event_id], expiry_time.strftime("%s"))

    return True


def title(event):
    return f"A new user account was created - [{event.udm('user')}]"
