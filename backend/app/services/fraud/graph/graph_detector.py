from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Any
import networkx as nx
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.blacklist import BlacklistedEntity
from app.models.enums import TransactionStatus


class GraphFraudDetector:
    def __init__(self):
        pass

    def evaluate_network(
        self, 
        transaction: Transaction, 
        db: Session
    ) -> Tuple[float, List[str], List[int]]:
        """
        Builds a NetworkX graph from database records and computes path distance 
        from the current transaction entity to known blacklisted or fraud nodes.
        
        Returns:
            graph_risk_score: float (0.0 - 100.0)
            detected_patterns: List[str]
            connected_fraud_accounts: List[int] (user IDs)
        """
        try:
            # 1. Fetch transactions in the last 30 days to build the active relationship network
            time_limit = datetime.utcnow() - timedelta(days=30)
            recent_transactions = db.query(Transaction).filter(
                Transaction.created_at >= time_limit
            ).all()

            # Ensure the current transaction is represented (in case it is not yet committed)
            txs = list(recent_transactions)
            if all(t.id != transaction.id for t in txs if t.id is not None):
                txs.append(transaction)

            # 2. Build the Graph
            G = nx.Graph()
            
            # Nodes are prefixed to prevent collision:
            # u:user_id, d:device_id, r:receiver_name, ip:ip_address, m:merchant_category
            for t in txs:
                u_node = f"u:{t.sender_id}"
                
                # Add nodes and edges
                G.add_node(u_node, type="user", label=f"User {t.sender_id}")
                
                if t.device_id:
                    d_node = f"d:{t.device_id}"
                    G.add_node(d_node, type="device", label=t.device_id)
                    G.add_edge(u_node, d_node, relationship="used_device")
                    
                if t.receiver_name:
                    r_node = f"r:{t.receiver_name.lower()}"
                    G.add_node(r_node, type="receiver", label=t.receiver_name)
                    G.add_edge(u_node, r_node, relationship="sent_money")
                    
                if t.ip_address:
                    ip_node = f"ip:{t.ip_address}"
                    G.add_node(ip_node, type="ip", label=t.ip_address)
                    G.add_edge(u_node, ip_node, relationship="connected_ip")
                    
                if t.merchant_category:
                    m_node = f"m:{t.merchant_category.lower()}"
                    G.add_node(m_node, type="merchant", label=t.merchant_category)
                    G.add_edge(u_node, m_node, relationship="visited_merchant")

            # 3. Identify Suspicious / Blacklisted Nodes
            suspicious_nodes: Set[str] = set()
            suspicious_reasons: Dict[str, str] = {}

            # Query blacklists
            blacklisted_entities = db.query(BlacklistedEntity).filter(
                BlacklistedEntity.is_active == True
            ).all()

            for be in blacklisted_entities:
                node_key = None
                if be.entity_type == "receiver":
                    node_key = f"r:{be.entity_value.lower()}"
                elif be.entity_type == "device":
                    node_key = f"d:{be.entity_value}"
                elif be.entity_type == "ip":
                    node_key = f"ip:{be.entity_value}"

                if node_key and G.has_node(node_key):
                    suspicious_nodes.add(node_key)
                    suspicious_reasons[node_key] = f"Global Blacklist ({be.reason})"

            # Query historically blocked transactions (confirmed fraud)
            blocked_transactions = db.query(Transaction).filter(
                Transaction.status == TransactionStatus.BLOCKED
            ).all()

            for bt in blocked_transactions:
                # Add entities associated with confirmed fraud
                u_blocked = f"u:{bt.sender_id}"
                if G.has_node(u_blocked):
                    suspicious_nodes.add(u_blocked)
                    suspicious_reasons[u_blocked] = "Confirmed fraudulent account"
                    
                if bt.device_id:
                    d_blocked = f"d:{bt.device_id}"
                    if G.has_node(d_blocked):
                        suspicious_nodes.add(d_blocked)
                        suspicious_reasons[d_blocked] = "Used in blocked transaction"
                        
                if bt.ip_address:
                    ip_blocked = f"ip:{bt.ip_address}"
                    if G.has_node(ip_blocked):
                        suspicious_nodes.add(ip_blocked)
                        suspicious_reasons[ip_blocked] = "Associated with blocked transaction"

            # 4. Analyze Paths from the Current User
            curr_user = f"u:{transaction.sender_id}"
            
            if not G.has_node(curr_user):
                return 0.0, ["Isolated Node: No connections built yet"], []

            graph_risk_score = 0.0
            detected_patterns: List[str] = []
            connected_fraud_accounts: Set[int] = set()

            # For each suspicious node, check shortest path distance to our current user
            for s_node in suspicious_nodes:
                # Skip checking path to oneself
                if s_node == curr_user:
                    graph_risk_score = max(graph_risk_score, 80.0)
                    detected_patterns.append("Sender account is historically linked to confirmed fraud")
                    continue

                try:
                    # Calculate shortest path
                    path = nx.shortest_path(G, source=curr_user, target=s_node)
                    distance = len(path) - 1 # count edges, not nodes
                    
                    if distance == 1:
                        # Direct connection to a blacklisted entity (e.g. sent money to blacklist, or on blacklisted device)
                        risk = 95.0
                        graph_risk_score = max(graph_risk_score, risk)
                        pattern = f"Direct link (1 hop) to suspicious node '{s_node}': {suspicious_reasons[s_node]}"
                        if pattern not in detected_patterns:
                            detected_patterns.append(pattern)
                            
                    elif distance <= 3:
                        # Indirect connection (2 or 3 hops, e.g. sharing a device/IP with a fraudster)
                        risk = 65.0 if distance == 2 else 35.0
                        graph_risk_score = max(graph_risk_score, risk)
                        pattern = f"Indirect connection ({distance} hops) to suspicious node '{s_node}' via path {path}: {suspicious_reasons[s_node]}"
                        if pattern not in detected_patterns:
                            detected_patterns.append(pattern)
                            
                    # Extract any intermediate user IDs along this path
                    for node in path:
                        if node.startswith("u:") and node != curr_user:
                            user_id = int(node.split(":")[1])
                            connected_fraud_accounts.add(user_id)
                            
                except nx.NetworkXNoPath:
                    continue

            # Additional structural check: Circular money movement or shared device structures
            # Let's check if there are multiple accounts sharing the current transaction's device
            if transaction.device_id:
                d_curr = f"d:{transaction.device_id}"
                if G.has_node(d_curr):
                    neighbors = [n for n in G.neighbors(d_curr) if n.startswith("u:")]
                    if len(neighbors) >= 3:
                        # Device is shared across 3+ users
                        graph_risk_score = max(graph_risk_score, 40.0)
                        pattern = f"Shared device structure: Device {transaction.device_id} is shared by {len(neighbors)} accounts"
                        if pattern not in detected_patterns:
                            detected_patterns.append(pattern)

            return float(graph_risk_score), detected_patterns, list(connected_fraud_accounts)

        except Exception as e:
            import logging
            logging.getLogger("uvicorn.error").error(f"Error in Graph Fraud Detection: {e}")
            return 0.0, [f"Graph evaluation error: {str(e)}"], []
