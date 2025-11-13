import networkx as nx
from pydantic import BaseModel
from typing import List

class AttackEvent(BaseModel):
    log_id: int
    attack_type: str
    source_ip: str
    payload: str
    twin_instance_id: str | None = None

def build_graph(events: List[AttackEvent]) -> nx.Graph:
    G = nx.Graph()
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            event1 = events[i]
            event2 = events[j]
            weight = 0
            if event1.source_ip == event2.source_ip:
                weight += 5
            # Placeholder for signature overlap
            # if signature_overlap(event1, event2) > 0.5:
            #     weight += 10
            # Placeholder for same persona attribution
            # if attribute(event1).cluster == attribute(event2).cluster:
            #     weight += 5
            if event1.twin_instance_id == event2.twin_instance_id:
                weight += 3
            if weight > 0:
                G.add_edge(event1.log_id, event2.log_id, weight=weight)
    return G
