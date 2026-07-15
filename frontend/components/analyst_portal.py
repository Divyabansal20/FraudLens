import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import matplotlib.pyplot as plt
import re
import ast
import numpy as np
from datetime import datetime
from utils.api_client import api_client

def draw_network_graph(tx_details, graph_details):
    """
    Renders a visual NetworkX node diagram of the transaction relationships.
    Colors blacklisted or suspicious entities in red.
    """
    G = nx.Graph()
    curr_user = f"u:{tx_details['sender_id']}"
    
    # Helper to add node with category details
    def add_network_node(node_id, is_suspicious=False):
        if node_id.startswith("u:"):
            label = f"User {node_id.split(':')[1]}"
            cat = "user"
        elif node_id.startswith("d:"):
            label = f"Device:\n{node_id.split(':')[1]}"
            cat = "device"
        elif node_id.startswith("ip:"):
            label = f"IP:\n{node_id.split(':')[1]}"
            cat = "ip"
        elif node_id.startswith("r:"):
            label = f"Receiver:\n{node_id.split(':')[1].title()}"
            cat = "receiver"
        elif node_id.startswith("m:"):
            label = f"Merchant:\n{node_id.split(':')[1].title()}"
            cat = "merchant"
        else:
            label = node_id
            cat = "unknown"
            
        G.add_node(node_id, label=label, category=cat, suspicious=is_suspicious)

    # 1. Extract paths from detected patterns
    patterns = graph_details.get("detected_patterns", [])
    suspicious_nodes = set()
    paths_to_draw = []
    
    for pat in patterns:
        # Look for path list pattern like: ['u:11', 'm:retail', 'u:9', 'd:One_plus_nord_5']
        match = re.search(r"via path\s+(\[.*?\])", pat)
        if match:
            try:
                # Parse list string, e.g. "['u:11', 'm:retail']"
                path_list = ast.literal_eval(match.group(1))
                if isinstance(path_list, list) and len(path_list) > 1:
                    paths_to_draw.append(path_list)
                    suspicious_nodes.add(path_list[-1])
            except Exception as e:
                pass
        else:
            match_direct = re.search(r"suspicious node '(.*?)'", pat)
            if match_direct:
                s_node = match_direct.group(1)
                suspicious_nodes.add(s_node)
                paths_to_draw.append([curr_user, s_node])

    # CRITICAL CLEANUP: Filter out any path that goes through merchant category nodes ('m:retail' etc.)
    # to eliminate massive, useless, safe connection loops.
    paths_to_draw = [p for p in paths_to_draw if not any(node.startswith('m:') for node in p)]

    # If no threat paths were found after filtering (or if it was a safe transaction), draw the basic starburst of current entities
    if not paths_to_draw:
        add_network_node(curr_user)
        curr_device = f"d:{tx_details['device_id']}" if tx_details.get('device_id') else None
        curr_receiver = f"r:{tx_details['receiver_name'].lower()}" if tx_details.get('receiver_name') else None
        curr_ip = f"ip:{tx_details['ip_address']}" if tx_details.get('ip_address') else None
        
        if curr_device:
            add_network_node(curr_device)
            G.add_edge(curr_user, curr_device)
        if curr_receiver:
            add_network_node(curr_receiver)
            G.add_edge(curr_user, curr_receiver)
        if curr_ip:
            add_network_node(curr_ip)
            G.add_edge(curr_user, curr_ip)
    else:
        # Draw ONLY the threat paths to keep the visualization highly readable and focused
        for path_list in paths_to_draw:
            for i in range(len(path_list)):
                node_id = path_list[i]
                is_target = (i == len(path_list) - 1)
                add_network_node(node_id, is_suspicious=is_target)
                if i > 0:
                    G.add_edge(path_list[i-1], path_list[i])

    # Assign colors and borders based on entity type
    color_map = []
    edge_colors = []
    linewidths = []
    labels = {}
    for node in G.nodes():
        node_data = G.nodes[node]
        labels[node] = node_data.get("label", node)
        
        # Color logic: Fraud target is red, current user is blue, others based on entity type
        if node_data.get("suspicious", False) or node in suspicious_nodes:
            color_map.append("#de2d26")  # Crimson Red for threats
            edge_colors.append("#330000")
            linewidths.append(1.5)
        elif node == curr_user:
            color_map.append("#3182bd")  # Safe Subject Blue
            edge_colors.append("#08519c")
            linewidths.append(1.5)
        else:
            cat = node_data.get("category", "unknown")
            if cat == "user":
                color_map.append("#fdd0a2")  # Orange for other users
                edge_colors.append("#d94801")
                linewidths.append(1.0)
            elif cat == "device":
                color_map.append("#a1d99b")  # Green for hardware devices
                edge_colors.append("#006d2c")
                linewidths.append(1.0)
            elif cat == "ip":
                color_map.append("#dadaeb")  # Purple for IP nodes
                edge_colors.append("#54278f")
                linewidths.append(1.0)
            elif cat == "receiver":
                color_map.append("#fa9fb5")  # Pink for receivers
                edge_colors.append("#ae017e")
                linewidths.append(1.0)
            else:
                color_map.append("#e0e0e0")  # Safe gray for others
                edge_colors.append("#666666")
                linewidths.append(1.0)

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    
    # Use spring layout with large spacing (k=2.0) to ensure clear visualization
    pos = nx.spring_layout(G, k=2.0, seed=42)
    
    # 1. Draw Edges
    nx.draw_networkx_edges(G, pos, edge_color="#cccccc", width=1.5, ax=ax)
    
    # 2. Draw Nodes as large colored circles
    nx.draw_networkx_nodes(
        G, pos, node_color=color_map, node_size=900,
        edgecolors=edge_colors, linewidths=linewidths, ax=ax
    )
    
    # 3. Offset labels slightly below nodes to keep node colors visible
    pos_labels = {k: v - np.array([0, 0.15]) for k, v in pos.items()}
    nx.draw_networkx_labels(
        G, pos_labels, labels=labels, font_size=8, font_color="#111111",
        font_weight="bold", ax=ax
    )
    
    # Pad margins to prevent labels from being clipped at the edges
    ax.margins(0.2)
    ax.axis("off")
    
    # Set background color to match dashboard layout
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#ffffff')
    plt.tight_layout()
    return fig

def render_graph_connection_audit(patterns):
    """
    Renders all graph connection path alerts into a single cohesive,
    structured markdown container for the analyst to audit.
    """
    if not patterns:
        return

    direct_links = []
    indirect_links = []
    shared_devices = []
    other_patterns = []

    for p in patterns:
        if "Direct link" in p:
            direct_links.append(p)
        elif "Indirect connection" in p:
            indirect_links.append(p)
        elif "Shared device" in p:
            shared_devices.append(p)
        else:
            other_patterns.append(p)

    content = []
    content.append("### 🕸️ Graph Network Relationship Audit")
    content.append("A consolidated review of relationship connections and shared entity footprints detected by the network graph engine:")
    content.append("---")

    if direct_links:
        content.append("#### 🚨 Direct Threat Connections (1-Hop)")
        content.append("The transaction is directly connected to blacklisted or confirmed fraudulent entities:")
        for dl in direct_links:
            clean = dl.replace("Direct link (1 hop) to suspicious node ", "Link to ").replace("'", "`")
            content.append(f"- **{clean}**")
        content.append("")

    if indirect_links:
        content.append("#### ⚠️ Shared Footprint & Hop Analysis")
        content.append("The relation graph has traced multi-hop paths to flagged/suspended nodes, revealing shared device, location, or IP footprints:")
        for il in indirect_links:
            clean = il.replace("Indirect connection ", "").replace("to suspicious node ", "").replace("via path ", "through ").replace("'", "`")
            content.append(f"- **{clean}**")
        content.append("")

    if shared_devices:
        content.append("#### 📱 Syndicate & Device-Sharing Activity")
        content.append("Multiple distinct user accounts have processed payments using the same hardware device fingerprint:")
        for sd in shared_devices:
            content.append(f"- **{sd}**")
        content.append("")

    if other_patterns:
        content.append("#### 🔍 Structural Indicators")
        for op in other_patterns:
            content.append(f"- **{op}**")
        content.append("")

    with st.container(border=True):
        st.markdown("\n".join(content))

def render_analyst_portal(token: str, user_profile: dict):
    st.subheader("FraudLens Investigator Workspace")
    st.markdown("Monitor high-risk queues, inspect machine learning anomaly profiles, and audit relation networks.")

    # Load data for metrics
    try:
        review_queue = api_client.get_analyst_queue(token)
        blocked_queue = api_client.get_analyst_blocked(token)
    except Exception as e:
        st.error(f"Error fetching queues from backend: {e}")
        return

    # Visual statistics summary cards
    col_metric1, col_metric2, col_metric3 = st.columns(3)
    with col_metric1:
        st.metric("Review Queue Size", len(review_queue), delta=f"+{len(review_queue)}" if len(review_queue) > 0 else None, delta_color="inverse")
    with col_metric2:
        st.metric("Total Auto-Blocked", len(blocked_queue))
    with col_metric3:
        st.metric("Active Learning Model Status", "Retrained & Active" if len(blocked_queue) > 2 else "Collecting Feedback")

    tab_review, tab_blocked = st.tabs(["Pending Review Queue", "Auto-Blocked Archive"])

    with tab_review:
        if not review_queue:
            st.success("Review queue is completely clean! No pending investigations.")
        else:
            st.markdown("### Labeled Flag Holds")
            st.markdown("Below are the transactions pending investigator audit.")
            
            queue_data = []
            for t in review_queue:
                try:
                    dt = datetime.fromisoformat(t["created_at"]).strftime("%Y-%m-%d %H:%M")
                except:
                    dt = t["created_at"]
                queue_data.append({
                    "Transaction ID": t["id"],
                    "Sender ID": t["sender_id"],
                    "Receiver": t["receiver_name"],
                    "Amount (INR)": f"₹{t['amount']:,}",
                    "Device": t["device_id"],
                    "Location": t["city"],
                    "Risk Score": t.get("aggregated_score", "N/A"),
                    "Date": dt
                })
            st.dataframe(pd.DataFrame(queue_data), use_container_width=True, hide_index=True)

            # Select transaction dropdown in a separate visual selector block
            st.markdown("---")
            st.markdown("### Select a Transaction to Run Audit")
            review_options = {
                f"ID #{t['id']} | User {t['sender_id']} to {t['receiver_name']} (₹{t['amount']:,}) - Score: {t.get('aggregated_score', 'N/A')}": t
                for t in review_queue
            }
            selected_tx_label = st.selectbox("Active Case Target", list(review_options.keys()))
            
            if selected_tx_label:
                selected_tx = review_options[selected_tx_label]
                
                # Fetch detailed evaluation
                try:
                    with st.spinner("Fetching full risk evaluation report..."):
                        evaluation = api_client.get_transaction_evaluation(token, selected_tx["id"])
                except Exception as e:
                    st.error(f"Failed to fetch evaluation details: {e}")
                    return

                # Visual Divider separating case file from selection dropdown
                st.markdown("---")
                st.markdown(f"## Transaction Case File: ID #{selected_tx['id']}")

                # AI Copilot Case Briefing (RAG Briefing)
                with st.container(border=True):
                    st.markdown("### 🤖 AI Copilot Case Briefing (RAG)")
                    ai_summary = evaluation.get("ai_investigation_summary", "Retrieving similar fraud precedents...")
                    ai_rec = evaluation.get("ai_recommendation", "Formulating action plan...")
                    
                    col_brief_sum, col_brief_rec = st.columns([2, 1])
                    with col_brief_sum:
                        st.markdown(f"**Investigation Summary:**\n{ai_summary}")
                    with col_brief_rec:
                        st.warning(f"**AI Recommendation:**\n\n{ai_rec}")

                # 1. Transaction Summary Block
                with st.container(border=True):
                    st.markdown("#### Transaction Summary")
                    col_det1, col_det2, col_det3, col_det4 = st.columns(4)
                    with col_det1:
                        st.markdown(f"**Transaction ID**: {selected_tx['id']}\n\n**Sender ID**: {selected_tx['sender_id']}")
                    with col_det2:
                        st.markdown(f"**Receiver Name**: {selected_tx['receiver_name']}\n\n**Amount**: ₹{selected_tx['amount']:,}")
                    with col_det3:
                        st.markdown(f"**Device ID**: {selected_tx['device_id']}\n\n**Payment Method**: {selected_tx['payment_method']}")
                    with col_det4:
                        st.markdown(f"**Location**: {selected_tx['city']}, {selected_tx['country']}\n\n**Submitted**: {datetime.fromisoformat(selected_tx['created_at']).strftime('%Y-%m-%d %H:%M') if 'created_at' in selected_tx else 'N/A'}")
                    
                    st.markdown("---")
                    # Risk Aggregation inside summary
                    score = evaluation.get("aggregated_score", 0.0)
                    col_score, col_conf = st.columns([2, 1])
                    with col_score:
                        if score >= 80.0:
                            st.error(f"Aggregated Score: **{score}/100** (CRITICAL RISK)")
                        elif score >= 38.0:
                            st.warning(f"Aggregated Score: **{score}/100** (MEDIUM RISK)")
                        else:
                            st.success(f"Aggregated Score: **{score}/100** (LOW RISK)")
                    with col_conf:
                        st.info(f"System Confidence: {evaluation.get('confidence', 0.5) * 100:.0f}%")

                # 2. Rule Engine Trigger Status (Full Width Horizontal Table under Metadata summary)
                with st.container(border=True):
                    st.markdown("#### Triggered Security Rules")
                    
                    # Build a clean 2-column dataframe of rules
                    rules_data = []
                    for rule in evaluation.get("triggered_rules", []):
                        status_str = "TRIGGERED" if rule.get("triggered", False) else "SAFE"
                        contrib_val = f"+{rule.get('score_contribution')}" if rule.get("triggered", False) else "0.0"
                        check_name = f"{rule.get('rule_name')} ({status_str} | Contrib: {contrib_val})"
                        rules_data.append({
                            "Security Check": check_name,
                            "Findings & Rationale": rule.get("reason")
                        })
                    
                    if rules_data:
                        st.dataframe(pd.DataFrame(rules_data), use_container_width=True, hide_index=True)
                    else:
                        st.info("No security rules triggered.")

                # 3. Engine Diagnostics Audits
                st.markdown("### Engine Diagnostics Audits")
                col_ml, col_graph, col_behavior = st.columns(3)
                
                with col_ml:
                    with st.container(border=True):
                        st.markdown("#### Machine Learning Anomaly Diagnostics")
                        ml_details = evaluation.get("ml_details", {})
                        st.metric("ML Anomaly Score", f"{ml_details.get('anomaly_score', 0.0)}/100")
                        
                        contribs = ml_details.get("feature_contributions", {})
                        if contribs:
                            df_contribs = pd.DataFrame([
                                {"Feature": feat.replace("_", " ").title(), "Contribution": weight * 100}
                                for feat, weight in contribs.items()
                            ])
                            fig = px.bar(
                                df_contribs, x="Contribution", y="Feature", orientation="h",
                                title="Feature Contribution Weights (%)",
                                color_discrete_sequence=["#1f77b4"]
                            )
                            fig.update_layout(height=200, margin=dict(l=0, r=0, t=30, b=0))
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.info("No feature contributions available.")

                with col_graph:
                    with st.container(border=True):
                        st.markdown("#### Graph Relationship Network Analysis")
                        graph_details = evaluation.get("graph_details", {})
                        st.metric("Graph Risk Score", f"{graph_details.get('risk_score', 0.0)}/100")
                        
                        fig_graph = draw_network_graph(selected_tx, graph_details)
                        st.pyplot(fig_graph)

                with col_behavior:
                    with st.container(border=True):
                        st.markdown("#### AI Behavior Profile Analysis")
                        drift_score = evaluation.get("behavior_drift_score", 0.0)
                        st.metric("Behavior Drift Score", f"{drift_score}/100")
                        
                        st.write("Deviation Rationale:")
                        if drift_score >= 80.0:
                            st.error("Critical Profile Shift: Payment pattern strongly deviates from user history.")
                        elif drift_score >= 40.0:
                            st.warning("Moderate Profile Shift: Spend amount or device does not match standard habits.")
                        else:
                            st.success("Normal profile alignment: Pattern matches customer transaction records.")

                # Pattern alerts below ML, Graph, and Behavior pictures
                patterns = graph_details.get("detected_patterns", [])
                if patterns:
                    render_graph_connection_audit(patterns)

                # 4. AI/LLM Security Explanations (Full width, stacked vertically)
                st.markdown("### AI Generative Explanations")
                with st.container(border=True):
                    st.info(f"**Customer-Facing Security Notice**\n\n\"{evaluation.get('customer_explanation', 'N/A')}\"")
                    st.info(f"**Investigator Security Analysis Summary**\n\n{evaluation.get('analyst_explanation', 'N/A')}")

                # 5. Analyst Decision Input Form
                st.markdown("### Case Override Resolution")
                with st.container(border=True):
                    with st.form("decision_form"):
                        notes = st.text_area("Audit Log Notes", placeholder="Provide investigation findings and action rationale...")
                        
                        col_app, col_rej = st.columns(2)
                        with col_app:
                            submit_approve = st.form_submit_button("Clear & Approve Transaction", use_container_width=True)
                        with col_rej:
                            submit_reject = st.form_submit_button("Confirm Fraud & Permanently Block", use_container_width=True)

                        if submit_approve:
                            if not notes:
                                st.error("Please add resolution audit notes to approve.")
                            else:
                                try:
                                    api_client.submit_decision(token, selected_tx["id"], "FALSE_POSITIVE", notes)
                                    st.success("Decision Logged: Transaction cleared as False Positive! Supervised retraining queued.")
                                    st.toast("Retraining model in background task...")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Failed to submit decision: {e}")
                                    
                        if submit_reject:
                            if not notes:
                                st.error("Please add resolution audit notes to block.")
                            else:
                                try:
                                    api_client.submit_decision(token, selected_tx["id"], "CONFIRMED_FRAUD", notes)
                                    st.success("Decision Logged: Transaction blocked as Confirmed Fraud! Supervised retraining queued.")
                                    st.toast("Retraining model in background task...")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Failed to submit decision: {e}")

    with tab_blocked:
        st.markdown("### Suspended Payment Logs")
        if not blocked_queue:
            st.info("No auto-blocked transactions found.")
        else:
            blocked_data = []
            for b in blocked_queue:
                try:
                    dt = datetime.fromisoformat(b["created_at"]).strftime("%Y-%m-%d %H:%M")
                except:
                    dt = b["created_at"]
                blocked_data.append({
                    "ID": b["id"],
                    "Sender ID": b["sender_id"],
                    "Receiver": b["receiver_name"],
                    "Amount": f"₹{b['amount']:,}",
                    "Device": b["device_id"],
                    "City": b["city"],
                    "Aggregated Score": b.get("aggregated_score", "N/A"),
                    "Date": dt
                })
            df_blocked = pd.DataFrame(blocked_data)
            st.dataframe(df_blocked, use_container_width=True, hide_index=True)

            # Dropdown selector to inspect a specific blocked transaction
            st.markdown("---")
            st.markdown("### Select a Blocked Transaction to Run Audit")
            blocked_options = {
                f"ID #{b['id']} | User {b['sender_id']} to {b['receiver_name']} (₹{b['amount']:,}) - Score: {b.get('aggregated_score', 'N/A')}": b
                for b in blocked_queue
            }
            selected_blocked_label = st.selectbox(
                "Blocked Case Target", 
                list(blocked_options.keys()), 
                key="blocked_case_target"
            )
            
            if selected_blocked_label:
                selected_blocked_tx = blocked_options[selected_blocked_label]
                
                # Fetch detailed evaluation
                try:
                    with st.spinner("Fetching full risk evaluation report..."):
                        evaluation = api_client.get_transaction_evaluation(token, selected_blocked_tx["id"])
                except Exception as e:
                    st.error(f"Failed to fetch evaluation details: {e}")
                else:
                    # Visual Divider separating case file from selection dropdown
                    st.markdown("---")
                    st.markdown(f"## Blocked Transaction Case File: ID #{selected_blocked_tx['id']}")

                    # AI Copilot Case Briefing (RAG Briefing)
                    with st.container(border=True):
                        st.markdown("### 🤖 AI Copilot Case Briefing (RAG)")
                        ai_summary = evaluation.get("ai_investigation_summary", "Retrieving similar fraud precedents...")
                        ai_rec = evaluation.get("ai_recommendation", "Formulating action plan...")
                        
                        col_brief_sum, col_brief_rec = st.columns([2, 1])
                        with col_brief_sum:
                            st.markdown(f"**Investigation Summary:**\n{ai_summary}")
                        with col_brief_rec:
                            st.warning(f"**AI Recommendation:**\n\n{ai_rec}")

                    # 1. Transaction Summary Block
                    with st.container(border=True):
                        st.markdown("#### Transaction Summary")
                        col_det1, col_det2, col_det3, col_det4 = st.columns(4)
                        with col_det1:
                            st.markdown(f"**Transaction ID**: {selected_blocked_tx['id']}\n\n**Sender ID**: {selected_blocked_tx['sender_id']}")
                        with col_det2:
                            st.markdown(f"**Receiver Name**: {selected_blocked_tx['receiver_name']}\n\n**Amount**: ₹{selected_blocked_tx['amount']:,}")
                        with col_det3:
                            st.markdown(f"**Device ID**: {selected_blocked_tx['device_id']}\n\n**Payment Method**: {selected_blocked_tx['payment_method']}")
                        with col_det4:
                            st.markdown(f"**Location**: {selected_blocked_tx['city']}, {selected_blocked_tx.get('country', 'IN')}\n\n**Submitted**: {datetime.fromisoformat(selected_blocked_tx['created_at']).strftime('%Y-%m-%d %H:%M') if 'created_at' in selected_blocked_tx else 'N/A'}")
                        
                        st.markdown("---")
                        # Risk Aggregation inside summary
                        score = evaluation.get("aggregated_score", 0.0)
                        col_score, col_conf = st.columns([2, 1])
                        with col_score:
                            if score >= 80.0:
                                st.error(f"Aggregated Score: **{score}/100** (CRITICAL RISK)")
                            elif score >= 38.0:
                                st.warning(f"Aggregated Score: **{score}/100** (MEDIUM RISK)")
                            else:
                                st.success(f"Aggregated Score: **{score}/100** (LOW RISK)")
                        with col_conf:
                            st.info(f"System Confidence: {evaluation.get('confidence', 0.5) * 100:.0f}%")

                    # 2. Rule Engine Trigger Status
                    with st.container(border=True):
                        st.markdown("#### Triggered Security Rules")
                        
                        rules_data = []
                        for rule in evaluation.get("triggered_rules", []):
                            status_str = "TRIGGERED" if rule.get("triggered", False) else "SAFE"
                            contrib_val = f"+{rule.get('score_contribution')}" if rule.get("triggered", False) else "0.0"
                            check_name = f"{rule.get('rule_name')} (Status: {status_str} | Contrib: {contrib_val})"
                            rules_data.append({
                                "Security Check": check_name,
                                "Findings & Rationale": rule.get("reason")
                            })
                        
                        if rules_data:
                            st.dataframe(pd.DataFrame(rules_data), use_container_width=True, hide_index=True)
                        else:
                            st.info("No security rules triggered.")

                    # 3. Engine Diagnostics Audits
                    st.markdown("### Engine Diagnostics Audits")
                    col_ml, col_graph, col_behavior = st.columns(3)
                    
                    with col_ml:
                        with st.container(border=True):
                            st.markdown("#### Machine Learning Anomaly Diagnostics")
                            ml_details = evaluation.get("ml_details", {})
                            st.metric("ML Anomaly Score", f"{ml_details.get('anomaly_score', 0.0)}/100")
                            
                            contribs = ml_details.get("feature_contributions", {})
                            if contribs:
                                df_contribs = pd.DataFrame([
                                    {"Feature": feat.replace("_", " ").title(), "Contribution": weight * 100}
                                    for feat, weight in contribs.items()
                                ])
                                fig = px.bar(
                                    df_contribs, x="Contribution", y="Feature", orientation="h",
                                    title="Feature Contribution Weights (%)",
                                    color_discrete_sequence=["#1f77b4"]
                                )
                                fig.update_layout(height=200, margin=dict(l=0, r=0, t=30, b=0))
                                st.plotly_chart(fig, use_container_width=True)
                            else:
                                st.info("No feature contributions available.")

                    with col_graph:
                        with st.container(border=True):
                            st.markdown("#### Graph Relationship Network Analysis")
                            graph_details = evaluation.get("graph_details", {})
                            st.metric("Graph Risk Score", f"{graph_details.get('risk_score', 0.0)}/100")
                            
                            fig_graph = draw_network_graph(selected_blocked_tx, graph_details)
                            st.pyplot(fig_graph)

                    with col_behavior:
                        with st.container(border=True):
                            st.markdown("#### AI Behavior Profile Analysis")
                            drift_score = evaluation.get("behavior_drift_score", 0.0)
                            st.metric("Behavior Drift Score", f"{drift_score}/100")
                            
                            st.write("Deviation Rationale:")
                            if drift_score >= 80.0:
                                st.error("Critical Profile Shift: Payment pattern strongly deviates from user history.")
                            elif drift_score >= 40.0:
                                st.warning("Moderate Profile Shift: Spend amount or device does not match standard habits.")
                            else:
                                st.success("Normal profile alignment: Pattern matches customer transaction records.")

                    # Pattern alerts below ML and Graph
                    patterns = graph_details.get("detected_patterns", [])
                    if patterns:
                        render_graph_connection_audit(patterns)

                    # 4. AI/LLM Security Explanations
                    st.markdown("### AI Generative Explanations")
                    with st.container(border=True):
                        st.info(f"**Customer-Facing Security Notice**\n\n\"{evaluation.get('customer_explanation', 'N/A')}\"")
                        st.info(f"**Investigator Security Analysis Summary**\n\n{evaluation.get('analyst_explanation', 'N/A')}")

