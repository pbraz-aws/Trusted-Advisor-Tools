from datetime import datetime, timezone, timedelta
import collections
from typing import Any
import boto3

cloudtrail = boto3.client("cloudtrail")


def lambda_handler(event, context) -> dict[str, Any]:
    try:
        account_id = event["account"]
        time_discovered = event["time"]
        details = event["detail"]["check-item-detail"]
        username = details["User Name (IAM or Root)"]
        deleted_key = details["Access Key ID"]
        exposed_location = details["Location"]
        end_time = datetime.now(
            tz=timezone.utc
        )  # Create start and end time for CloudTrail lookup
        interval = timedelta(hours=24)
        start_time = end_time - interval
    except KeyError as e:
        print("Error: Invalid event data")
        print(e)
        raise (e)

    print("Retrieving events...")
    events = get_events(username, start_time, end_time)
    print("Summarizing events...")
    event_names, resource_names, resource_types = get_events_summaries(events)
    return {
        "account_id": account_id,
        "time_discovered": time_discovered,
        "username": username,
        "deleted_key": deleted_key,
        "exposed_location": exposed_location,
        "event_names": event_names,
        "resource_names": resource_names,
        "resource_types": resource_types,
    }


def get_events(username: str, starttime: datetime, endtime: datetime):
    """Retrieves detailed list of CloudTrail events that occured between the specified time interval.

    Args:
        username (string): Username to lookup CloudTrail events for.
        starttime(datetime): Start of interval to lookup CloudTrail events between.
        endtime(datetime): End of interval to lookup CloudTrail events between.

    Returns:
        (dict)
        Dictionary containing list of CloudTrail events occuring between the start and end time with detailed information for each event.

    """
    try:
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "Username", "AttributeValue": username},
            ],
            StartTime=starttime,
            EndTime=endtime,
            MaxResults=50,
        )
    except Exception as e:
        print(e)
        print(f"Unable to retrieve CloudTrail events for user {username} ")
        raise (e)
    return response


def get_events_summaries(events: dict):
    """Summarizes CloudTrail events list by reducing into counters of occurences for each event, resource name, and resource type in list.

    Args:
        events (dict): Dictionary containing list of CloudTrail events to be summarized.

    Returns:
        (list, list, list)
        Lists containing name:count tuples of most common occurences of events, resource names, and resource types in events list.

    """
    event_name_counter = collections.Counter()
    resource_name_counter = collections.Counter()
    resource_type_counter = collections.Counter()
    for event in events["Events"]:
        resources = event.get("Resources")
        event_name_counter.update([event.get("EventName")])
        if resources is not None:
            resource_name_counter.update(
                [resource.get("ResourceName") for resource in resources]
            )
            resource_type_counter.update(
                [resource.get("ResourceType") for resource in resources]
            )
    return (
        event_name_counter.most_common(10),
        resource_name_counter.most_common(10),
        resource_type_counter.most_common(10),
    )
