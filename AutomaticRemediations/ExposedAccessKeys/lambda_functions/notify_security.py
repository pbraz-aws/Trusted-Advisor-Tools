############################################################
# Authors: Manas Satpathi, Paul Brazell
# Company: AWS
# Date: April 2025
# Notes: Updated to send email & slack notification
############################################################
import json
import os
from typing import Any
import boto3
import urllib.request

TOPIC_ARN = os.getenv("TOPIC_ARN")  # ARN for SNS topic to post message to
slack_webhook_url = os.getenv("SlackWebhook_URL")

TEMPLATE = """At {} the IAM access key {} for user {} on account {} was deleted after it was found to have been exposed at the URL {}.
Below are summaries of the most recent actions, resource names, and resource types associated with this user over the last 24 hours.

Actions:
{}

Resource Names:
{}

Resource Types:
{}

These are summaries of only the most recent API calls made by this user. Please ensure your account remains secure by further reviewing the API calls made by this user in CloudTrail."""

sns = boto3.client("sns")


def lambda_handler(event, context):
    subject, message = create_message_from_event(event)

    publish_msg(subject, message)

    if not slack_webhook_url:
        print("Slack_URL is empty!")
        return

    notify_slack(subject, " An email is sent with details.")

    return {"statusCode": 200}


def create_message_from_event(event: dict[str, Any]) -> tuple[str, str]:
    account_id = event["account_id"]
    username = event["username"]
    deleted_key = event["deleted_key"]
    exposed_location = event["exposed_location"]
    time_discovered = event["time_discovered"]
    event_names = event["event_names"]
    resource_names = event["resource_names"]
    resource_types = event["resource_types"]

    
    subject = (
        f"Security Alert! IAM Access Key Exposed For User {username} On Account {account_id}!!"
    )
    print("Generating message body...")
    event_summary = generate_summary_str(event_names)
    rname_summary = generate_summary_str(resource_names)
    rtype_summary = generate_summary_str(resource_types)
    message = TEMPLATE.format(
        time_discovered,
        deleted_key,
        username,
        account_id,
        exposed_location,
        event_summary,
        rname_summary,
        rtype_summary,
    )

    return subject, message


def generate_summary_str(summary_items: list) -> str:
    """Generates formatted string containing CloudTrail summary info.

    Args:
        summary_items (list): List of tuples containing CloudTrail summary info.

    Returns:
        str: Formatted string containing CloudTrail summary info.
    """
    if not summary_items:
        return ""
        
    return "\t" + "\n\t".join(
        f"{item[0]}: {item[1]}" 
        for item in summary_items
    )


def publish_msg(subject: str, message: str) -> bool:
    """Publishes message to SNS topic.

    Args:
        subject (str): Subject of message to be published to topic.
        message (str): Content of message to be published to topic.

    Returns:
        bool: True if message was published successfully, False otherwise.
    """
    if not TOPIC_ARN:
        print("Missing TOPIC_ARN configuration")
        return False

    try:
        response = sns.publish(
            TopicArn=TOPIC_ARN,
            Message=message,
            Subject=subject,
            MessageStructure="string",
        )

        if response and response.get("MessageId"):
            print(f"Message published successfully. MessageId: {response['MessageId']}")
            return True

        print("Message publication failed - no MessageId received")
        return False

    except sns.exceptions.NotFoundException:
        print(f"SNS topic '{TOPIC_ARN}' not found")
        return False
    except sns.exceptions.InvalidParameterException:
        print("Invalid parameter in SNS publish request")
        return False
    except Exception as e:
        print(f"Failed to publish message to SNS topic '{TOPIC_ARN}': {str(e)}")
        return False


def notify_slack(subject, subject2):
    """
    Send notification to Slack using webhook URL.
    Args:
        subject (str): First part of the message
        subject2 (str): Second part of the message
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        assert slack_webhook_url is not None

        if not slack_webhook_url.lower().startswith("https://hooks.slack.com"):
            print("Invalid SlackWebhookURL")
            return

        # Construct JSON payload
        payload = {"content": f"{subject}{subject2}"}
        data = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json"}

        with urllib.request.urlopen(
            urllib.request.Request(slack_webhook_url, data=data, headers=headers)
        ) as response:
            if response.status == 200:
                print(f"Successfully sent Slack notification")
                return True
            else:
                print(f"Failed to send Slack notification. Status: {response.status}")
                return False

    except Exception as e:
        print(f"Error sending Slack notification: {str(e)}")
        return False
