from typing import Any, Dict


def send_notification(channel: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    # TODO: integrate Slack/email/pager
    return {"channel": channel, "status": "queued"}
