from collections.abc import Mapping

from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    # EC2 Volume snapshot made public
    if event.get("eventName") == "ModifySnapshotAttribute":
        parameters = event.get("requestParameters", {})
        if parameters.get("attributeType") != "CREATE_VOLUME_PERMISSION":
            return False

        items = deep_get(parameters, "createVolumePermission", "add", "items", default=[])
        for item in items:
            if not isinstance(item, (Mapping, dict)):
                continue
            if item.get("group") == "all":
                return True
        return False

    # RDS snapshot made public
    if event.get("eventName") == "ModifyDBClusterSnapshotAttribute":
        return "all" in deep_get(event, "requestParameters", "valuesToAdd", default=[])

    return False


def title(event):
    if event.get("eventName") == "ModifySnapshotAttribute":
        aws_service = "EC2"
    elif event.get("eventName") == "ModifyDBClusterSnapshotAttribute":
        aws_service = "RDS"
    return f"An {aws_service} snapshot was made public"
