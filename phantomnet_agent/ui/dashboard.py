from typing import List, Dict

def screen_overview(events: List[Dict], campaign_clusters: List[Dict]) -> Dict:
    total_events = len(events)
    active_campaigns = len(campaign_clusters)
    # Placeholder for average threat score
    avg_threat_score = 75

    latest_events = []
    for event in events[:10]:
        latest_events.append(
            {
                "ts": event["timestamp"],
                "src_ip": event["source_ip"],
                "attribution_cluster": event["attribution"]["cluster"],
                "threat_score": event["threat_score"]["score"],
            }
        )

    return {
        "section": "overview",
        "cards": [
            {"title": "Total Events", "value": total_events},
            {"title": "Active Campaigns", "value": active_campaigns},
            {"title": "Average Threat Score (24h)", "value": avg_threat_score},
        ],
        "tables": [
            {
                "title": "Latest Events",
                "rows": latest_events,
            }
        ],
    }

def screen_event(event: Dict) -> Dict:
    return {
        "section": "event_detail",
        "cards": [
            {"title": "Persona Selected", "value": event["persona"]},
            {"title": "Threat Score", "value": event["threat_score"]["score"]},
            {"title": "Attribution", "value": event["attribution"]["cluster"]},
            {"title": "Recommended Countermeasure", "value": event["countermeasure"]["action"]},
        ],
        "signatures": event["signatures"],
    }

def screen_campaign(campaign: Dict) -> Dict:
    return {
        "section": "campaign_detail",
        "cards": [
            {"title": "# Events in Cluster", "value": len(campaign["events"])},
            {"title": "Cluster Score", "value": campaign["cluster_score"]},
        ],
        "summary": campaign["summary"],
        "tables": [
            {
                "title": "Events in Campaign",
                "rows": campaign["events"],
            }
        ],
    }
