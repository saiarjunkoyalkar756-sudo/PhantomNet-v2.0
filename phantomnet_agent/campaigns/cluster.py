import networkx as nx
from pydantic import BaseModel
from typing import List

class Campaign(BaseModel):
    id: str
    events: List[str]  # event ids
    cluster_score: float
    summary: str

def detect_campaigns(graph: nx.Graph) -> List[Campaign]:
    campaigns = []
    for i, c in enumerate(nx.connected_components(graph)):
        subgraph = graph.subgraph(c)
        cluster_score = subgraph.size(weight="weight") / subgraph.number_of_nodes()
        campaigns.append(
            Campaign(
                id=f"campaign-{i}",
                events=list(subgraph.nodes()),
                cluster_score=cluster_score,
                summary="Placeholder summary"
            )
        )
    return campaigns
