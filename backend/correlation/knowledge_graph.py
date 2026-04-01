"""Knowledge Graph – in-memory graph of attack relationships for SentinelMesh XDR."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Node and Edge types
# ---------------------------------------------------------------------------

class NodeType:
    IP = "ip"
    USER = "user"
    HOST = "host"
    PROCESS = "process"
    ALERT = "alert"
    INCIDENT = "incident"
    DOMAIN = "domain"
    FILE = "file"
    CAMPAIGN = "campaign"


class EdgeType:
    ATTACKED = "attacked"
    CONNECTED_TO = "connected_to"
    EXECUTED = "executed"
    TRIGGERED = "triggered"
    RELATES_TO = "relates_to"
    LATERAL_MOVE = "lateral_move"
    AUTHENTICATED_AS = "authenticated_as"
    OWNS = "owns"
    PART_OF = "part_of"
    EXFILTRATED_TO = "exfiltrated_to"


@dataclass
class Node:
    """A vertex in the knowledge graph."""

    node_id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Edge:
    """A directed edge in the knowledge graph."""

    edge_id: str
    from_node: str
    to_node: str
    edge_type: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "edge_type": self.edge_type,
            "weight": self.weight,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Knowledge Graph
# ---------------------------------------------------------------------------

class KnowledgeGraph:
    """
    In-memory directed property graph of attack relationships.

    Supports:
      - Node/edge CRUD
      - BFS path discovery
      - Degree-based pivot point detection
      - Weakly-connected component detection
      - JSON export for frontend visualisation
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}
        # Adjacency: node_id → set of edge_ids going OUT
        self._adj_out: Dict[str, Set[str]] = defaultdict(set)
        # Adjacency: node_id → set of edge_ids coming IN
        self._adj_in: Dict[str, Set[str]] = defaultdict(set)
        self._log = logger.bind(component="KnowledgeGraph")

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(
        self,
        node_id: Optional[str] = None,
        node_type: str = NodeType.HOST,
        label: str = "",
        properties: Optional[Dict[str, Any]] = None,
    ) -> Node:
        """Add a node (or update if it already exists)."""
        nid = node_id or str(uuid.uuid4())
        if nid in self._nodes:
            # Merge properties
            existing = self._nodes[nid]
            if properties:
                existing.properties.update(properties)
            existing.updated_at = datetime.now(timezone.utc)
            return existing

        node = Node(
            node_id=nid,
            node_type=node_type,
            label=label or nid,
            properties=properties or {},
        )
        self._nodes[nid] = node
        self._adj_out[nid]  # ensure entry exists
        self._adj_in[nid]   # ensure entry exists
        self._log.debug("node_added", node_id=nid, node_type=node_type)
        return node

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            return False
        # Remove all adjacent edges
        for eid in list(self._adj_out.get(node_id, set())):
            self._remove_edge_by_id(eid)
        for eid in list(self._adj_in.get(node_id, set())):
            self._remove_edge_by_id(eid)
        del self._nodes[node_id]
        self._adj_out.pop(node_id, None)
        self._adj_in.pop(node_id, None)
        return True

    def find_nodes_by_type(self, node_type: str) -> List[Node]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def find_nodes_by_label(self, label: str) -> List[Node]:
        return [n for n in self._nodes.values() if n.label == label]

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self,
        from_node: str,
        to_node: str,
        edge_type: str = EdgeType.RELATES_TO,
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
        edge_id: Optional[str] = None,
    ) -> Optional[Edge]:
        """
        Add a directed edge. Auto-creates nodes if they do not exist.
        Returns None if from_node == to_node (no self-loops).
        """
        if from_node == to_node:
            return None

        # Ensure nodes exist
        if from_node not in self._nodes:
            self.add_node(node_id=from_node)
        if to_node not in self._nodes:
            self.add_node(node_id=to_node)

        # Increment weight if edge already exists
        existing = self._find_edge(from_node, to_node, edge_type)
        if existing:
            existing.weight += weight
            existing.properties.update(properties or {})
            return existing

        eid = edge_id or str(uuid.uuid4())
        edge = Edge(
            edge_id=eid,
            from_node=from_node,
            to_node=to_node,
            edge_type=edge_type,
            weight=weight,
            properties=properties or {},
        )
        self._edges[eid] = edge
        self._adj_out[from_node].add(eid)
        self._adj_in[to_node].add(eid)
        return edge

    def _find_edge(self, from_node: str, to_node: str, edge_type: str) -> Optional[Edge]:
        for eid in self._adj_out.get(from_node, set()):
            e = self._edges[eid]
            if e.to_node == to_node and e.edge_type == edge_type:
                return e
        return None

    def _remove_edge_by_id(self, edge_id: str) -> None:
        edge = self._edges.pop(edge_id, None)
        if edge:
            self._adj_out[edge.from_node].discard(edge_id)
            self._adj_in[edge.to_node].discard(edge_id)

    def get_edge(self, edge_id: str) -> Optional[Edge]:
        return self._edges.get(edge_id)

    # ------------------------------------------------------------------
    # Neighbourhood queries
    # ------------------------------------------------------------------

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "out",
        edge_type: Optional[str] = None,
    ) -> List[Node]:
        """
        Return neighbouring nodes.
        direction: 'out' (successors), 'in' (predecessors), 'both'
        """
        neighbor_ids: Set[str] = set()

        if direction in ("out", "both"):
            for eid in self._adj_out.get(node_id, set()):
                e = self._edges[eid]
                if edge_type is None or e.edge_type == edge_type:
                    neighbor_ids.add(e.to_node)

        if direction in ("in", "both"):
            for eid in self._adj_in.get(node_id, set()):
                e = self._edges[eid]
                if edge_type is None or e.edge_type == edge_type:
                    neighbor_ids.add(e.from_node)

        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def get_edges_for_node(self, node_id: str, direction: str = "both") -> List[Edge]:
        eids: Set[str] = set()
        if direction in ("out", "both"):
            eids |= self._adj_out.get(node_id, set())
        if direction in ("in", "both"):
            eids |= self._adj_in.get(node_id, set())
        return [self._edges[eid] for eid in eids if eid in self._edges]

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------

    def find_path(
        self,
        start_id: str,
        end_id: str,
        edge_type: Optional[str] = None,
        max_depth: int = 10,
    ) -> Optional[List[str]]:
        """
        BFS shortest-path discovery.
        Returns list of node IDs from start to end, or None if unreachable.
        """
        if start_id not in self._nodes or end_id not in self._nodes:
            return None
        if start_id == end_id:
            return [start_id]

        visited: Set[str] = {start_id}
        queue: deque[Tuple[str, List[str]]] = deque([(start_id, [start_id])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for neighbor in self.get_neighbors(current, direction="out", edge_type=edge_type):
                if neighbor.node_id == end_id:
                    return path + [end_id]
                if neighbor.node_id not in visited:
                    visited.add(neighbor.node_id)
                    queue.append((neighbor.node_id, path + [neighbor.node_id]))
        return None

    def find_all_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 6,
    ) -> List[List[str]]:
        """DFS to find all simple paths (no cycle) up to max_depth."""
        all_paths: List[List[str]] = []
        self._dfs_paths(start_id, end_id, [start_id], set(), all_paths, max_depth)
        return all_paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: List[str],
        visited: Set[str],
        results: List[List[str]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth:
            return
        if current == target:
            results.append(list(path))
            return
        visited.add(current)
        for neighbor in self.get_neighbors(current, direction="out"):
            nid = neighbor.node_id
            if nid not in visited:
                path.append(nid)
                self._dfs_paths(nid, target, path, visited, results, max_depth)
                path.pop()
        visited.discard(current)

    # ------------------------------------------------------------------
    # Graph analytics
    # ------------------------------------------------------------------

    def get_degree(self, node_id: str) -> Dict[str, int]:
        """Return in-degree, out-degree and total degree for a node."""
        in_deg = len(self._adj_in.get(node_id, set()))
        out_deg = len(self._adj_out.get(node_id, set()))
        return {"in": in_deg, "out": out_deg, "total": in_deg + out_deg}

    def find_central_nodes(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Find top-N high-degree nodes (potential pivot points)."""
        ranked = sorted(
            self._nodes.keys(),
            key=lambda nid: len(self._adj_in.get(nid, set())) + len(self._adj_out.get(nid, set())),
            reverse=True,
        )
        return [
            {
                "node_id": nid,
                "label": self._nodes[nid].label,
                "node_type": self._nodes[nid].node_type,
                **self.get_degree(nid),
            }
            for nid in ranked[:top_n]
        ]

    def find_communities(self) -> List[List[str]]:
        """
        Simple weakly-connected component detection using BFS on undirected edges.
        Returns list of components (each a list of node IDs).
        """
        visited: Set[str] = set()
        components: List[List[str]] = []

        def bfs_undirected(start: str) -> List[str]:
            component: List[str] = []
            queue: deque[str] = deque([start])
            visited.add(start)
            while queue:
                nid = queue.popleft()
                component.append(nid)
                for nb in self.get_neighbors(nid, direction="both"):
                    if nb.node_id not in visited:
                        visited.add(nb.node_id)
                        queue.append(nb.node_id)
            return component

        for node_id in self._nodes:
            if node_id not in visited:
                comp = bfs_undirected(node_id)
                components.append(comp)

        components.sort(key=len, reverse=True)
        return components

    def find_attack_paths_from_ip(self, source_ip: str, max_depth: int = 8) -> List[List[str]]:
        """Find all paths originating from a given IP node."""
        # Find the node for this IP
        ip_nodes = [n for n in self.find_nodes_by_type(NodeType.IP) if n.label == source_ip]
        if not ip_nodes:
            return []

        paths: List[List[str]] = []
        for ip_node in ip_nodes:
            # Find alert/incident nodes as targets
            targets = self.find_nodes_by_type(NodeType.ALERT) + self.find_nodes_by_type(NodeType.INCIDENT)
            for target in targets:
                found = self.find_all_paths(ip_node.node_id, target.node_id, max_depth=max_depth)
                paths.extend(found)
        return paths

    # ------------------------------------------------------------------
    # Bulk ingestion helpers
    # ------------------------------------------------------------------

    def ingest_correlated_event(self, corr_event: Any) -> None:
        """
        Ingest a CorrelatedEvent (or dict) into the graph.
        Creates nodes and edges for IPs, users, hosts and alerts.
        """
        if hasattr(corr_event, "to_dict"):
            data = corr_event.to_dict()
        elif isinstance(corr_event, dict):
            data = corr_event
        else:
            return

        cid = data.get("correlation_id", str(uuid.uuid4()))
        alert_node = self.add_node(node_id=cid, node_type=NodeType.ALERT, label=f"Alert:{cid[:8]}")

        for ip in data.get("source_ips", []):
            ip_node = self.add_node(node_id=f"ip:{ip}", node_type=NodeType.IP, label=ip)
            self.add_edge(ip_node.node_id, alert_node.node_id, EdgeType.TRIGGERED)

        for user in data.get("users", []):
            u_node = self.add_node(node_id=f"user:{user}", node_type=NodeType.USER, label=user)
            self.add_edge(u_node.node_id, alert_node.node_id, EdgeType.TRIGGERED)

        for host in data.get("hosts", []):
            h_node = self.add_node(node_id=f"host:{host}", node_type=NodeType.HOST, label=host)
            self.add_edge(alert_node.node_id, h_node.node_id, EdgeType.ATTACKED)

    def ingest_alert(self, alert: Dict[str, Any]) -> None:
        """Ingest a raw alert dict into the graph."""
        aid = alert.get("id", str(uuid.uuid4()))
        alert_node = self.add_node(
            node_id=f"alert:{aid}",
            node_type=NodeType.ALERT,
            label=alert.get("title", "Alert")[:64],
            properties={"severity": alert.get("severity"), "mitre": alert.get("mitre_technique")},
        )
        if alert.get("ip_address"):
            ip_node = self.add_node(
                node_id=f"ip:{alert['ip_address']}",
                node_type=NodeType.IP,
                label=alert["ip_address"],
            )
            self.add_edge(ip_node.node_id, alert_node.node_id, EdgeType.TRIGGERED)

        if alert.get("user_id"):
            u_node = self.add_node(
                node_id=f"user:{alert['user_id']}",
                node_type=NodeType.USER,
                label=alert["user_id"],
            )
            self.add_edge(u_node.node_id, alert_node.node_id, EdgeType.TRIGGERED)

    # ------------------------------------------------------------------
    # Export / serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Export the full graph to a JSON-serialisable dict."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "stats": {
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "community_count": len(self.find_communities()),
                "top_pivots": self.find_central_nodes(5),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        communities = self.find_communities()
        pivots = self.find_central_nodes(5)
        node_type_counts: Dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            node_type_counts[n.node_type] += 1
        edge_type_counts: Dict[str, int] = defaultdict(int)
        for e in self._edges.values():
            edge_type_counts[e.edge_type] += 1

        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "community_count": len(communities),
            "largest_community_size": len(communities[0]) if communities else 0,
            "node_types": dict(node_type_counts),
            "edge_types": dict(edge_type_counts),
            "top_pivots": pivots,
        }

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes
