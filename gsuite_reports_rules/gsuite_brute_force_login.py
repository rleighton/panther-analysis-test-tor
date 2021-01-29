from panther_base_helpers import deep_get, gsuite_details_lookup


def rule(event):
    # Filter events
    if event['id'].get('applicationName') != 'login':
        return False

    # Pattern match this event to the recon actions
    details = details_lookup('login', ['login_failure'], event)
    return bool(details) and evaluate_threshold(
        '{}-GSuiteLoginFailedCounter'.format(
            event.get('actor', {}).get('email')),
        THRESH,
        THRESH_TTL,
    )


def title(event):
    return 'User [{}] exceeded the failed logins threshold'.format(
        event.get('actor', {}).get('email'))
