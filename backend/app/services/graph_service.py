import networkx as nx
from typing import Any

class AttackGraphService:
    def __init__(self):
        self.version = "v1.5.0-entity-graph"
        self.graph = nx.DiGraph()
        self._init_default_graph()

    def _init_default_graph(self):
        """Build baseline enterprise entity relationship network."""
        # Nodes: Person, Email, Domain, IP, Device, Organization, Threat
        nodes = [
            ("org_bput", {"label": "BPUT University", "type": "organization", "risk_level": "SAFE"}),
            ("org_corp", {"label": "Enterprise Global Corp", "type": "organization", "risk_level": "SAFE"}),
            ("person_ankit", {"label": "Ankit Kumar (SecOps Lead)", "type": "person", "risk_level": "SAFE"}),
            ("person_satya", {"label": "Satya Nadella (Exec)", "type": "person", "risk_level": "SAFE"}),
            ("email_ankit", {"label": "ankit.kumar@bput.ac.in", "type": "email", "risk_level": "SAFE"}),
            ("email_satya", {"label": "satya@microsoft.com", "type": "email", "risk_level": "SAFE"}),
            ("dom_bput", {"label": "bput.ac.in", "type": "domain", "risk_level": "SAFE"}),
            ("dom_msft", {"label": "microsoft.com", "type": "domain", "risk_level": "SAFE"}),
            ("dev_laptop", {"label": "Dell Precision (Corp HW-941)", "type": "device", "risk_level": "SAFE"}),
            ("ip_internal", {"label": "10.14.80.25 (HQ Campus)", "type": "ip", "risk_level": "SAFE"}),
            
            # Suspicious / Malicious Infiltration Nodes
            ("person_attacker", {"label": "Unknown Threat Actor (APT-39)", "type": "person", "risk_level": "CRITICAL"}),
            ("email_spoof", {"label": "satya@micros0ft-support.net", "type": "email", "risk_level": "CRITICAL"}),
            ("dom_typosquat", {"label": "micros0ft-support.net", "type": "domain", "risk_level": "CRITICAL"}),
            ("ip_attacker", {"label": "185.220.101.5 (Suspicious Exit Node)", "type": "ip", "risk_level": "CRITICAL"}),
            ("dev_rogue", {"label": "Linux / Python Requests (Unknown Fingerprint)", "type": "device", "risk_level": "HIGH"}),
            ("threat_phish", {"label": "THT-2026-PHISH-01 (Spearphish Campaign)", "type": "threat", "risk_level": "CRITICAL"})
        ]
        
        edges = [
            # Legitimate relations
            ("person_ankit", "email_ankit", {"relation": "owns_mailbox"}),
            ("email_ankit", "dom_bput", {"relation": "domain_of"}),
            ("dom_bput", "org_bput", {"relation": "registered_to"}),
            ("person_ankit", "dev_laptop", {"relation": "operates_device"}),
            ("dev_laptop", "ip_internal", {"relation": "assigned_ip"}),
            
            ("person_satya", "email_satya", {"relation": "official_identity"}),
            ("email_satya", "dom_msft", {"relation": "domain_of"}),
            
            # Malicious / Impersonation connections
            ("person_attacker", "email_spoof", {"relation": "created_alias"}),
            ("email_spoof", "dom_typosquat", {"relation": "hosted_on"}),
            ("dom_typosquat", "ip_attacker", {"relation": "resolves_to"}),
            ("person_attacker", "dev_rogue", {"relation": "originates_from"}),
            ("dev_rogue", "ip_attacker", {"relation": "routes_through"}),
            ("email_spoof", "person_satya", {"relation": "impersonates"}),
            ("threat_phish", "email_ankit", {"relation": "targets_recipient"}),
            ("email_spoof", "threat_phish", {"relation": "payload_source"})
        ]

        self.graph.clear()
        for nid, attrs in nodes:
            self.graph.add_node(nid, **attrs)
        for u, v, attrs in edges:
            self.graph.add_edge(u, v, **attrs)

    def get_graph_data(self) -> dict[str, Any]:
        """Returns nodes and edges formatted for interactive UI graph visualization."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": str(n),
                "label": data.get("label", str(n)),
                "type": data.get("type", "unknown"),
                "risk_level": data.get("risk_level", "SAFE")
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "relation": data.get("relation", "connected_to")
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "metrics": {
                "total_entities": len(nodes),
                "total_relationships": len(edges),
                "critical_entities": sum(1 for n in nodes if n["risk_level"] == "CRITICAL")
            }
        }

    def generate_cypher_export(self) -> str:
        """Export graph as Neo4j Cypher statements for enterprise Neo4j clusters."""
        cypher_lines = ["// CyberGuard Enterprise Neo4j Export"]
        for n, data in self.graph.nodes(data=True):
            label = data.get("type", "Entity").capitalize()
            cypher_lines.append(
                f"MERGE (n:{label} {{id: '{n}'}}) "
                f"SET n.name = '{data.get('label')}', n.risk = '{data.get('risk_level')}';"
            )
        for u, v, data in self.graph.edges(data=True):
            rel = data.get("relation", "CONNECTED_TO").upper()
            cypher_lines.append(f"MATCH (a {{id: '{u}'}}), (b {{id: '{v}'}}) MERGE (a)-[:{rel}]->(b);")
        return "\n".join(cypher_lines)

attack_graph_service = AttackGraphService()
