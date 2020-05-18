import os
from ipaddress import ip_address
import boto3

# pylint: disable=no-member
KV_TABLE = boto3.resource('dynamodb',
                          os.environ.get('AWS_DEFAULT_REGION',
                                         'us-east-1')).Table('panther-kv-store')
# pylint: enable=no-member
THRESHOLD = 5


def helper_strip_role_session_id(user_identity_arn):
    # The Arn structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split('/')
    if arn_parts:
        return '/'.join(arn_parts[:2])
    return user_identity_arn


def get_user_identity_arn(event):
    user_identity = event.get('userIdentity', {})
    if user_identity.get('type') == 'AssumedRole':
        return helper_strip_role_session_id(user_identity.get('arn', ''))
    return user_identity.get('arn')


def reset(key: str):
    KV_TABLE.update_item(Key={'key': {
        'S': key
    }},
                         UpdateExpression='SET error_counter = 0')


def counter(user_arn: str) -> int:
    response = KV_TABLE.update_item(
        Key={
            'key': {'S': user_arn}
        },
        ReturnValues='UPDATED_NEW',
        UpdateExpression='SET error_counter = error_counter + :incr',
        ExpressionAttributeValues={
            ':incr': {'N': '1'}
        }
    )
    if 'Attributes' not in response:
        return 0

    return response['Attributes']['error_counter']['N']


def rule(event):
    if event.get('errorCode') != 'AccessDenied':
        return False

    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False

    user_identity_arn = get_user_identity_arn(event)
    current_counter = counter(user_identity_arn)
    if current_counter > THRESHOLD:
        reset(user_identity_arn)
        return True
    return False


def dedup(event):
    return get_user_identity_arn(event)


def title(event):
    user_identity = event.get('userIdentity')
    return 'Access denied to {} {}'.format(user_identity.get('type'),
                                           get_user_identity_arn(event))
