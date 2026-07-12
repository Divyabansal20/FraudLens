import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from utils.api_client import api_client

def draw_network_graph(tx_details, graph_details):
    """
    Renders a visual NetworkX node diagram of the transaction relationships.
    Colors blacklisted or suspicious entities in red.
    """
    G = nx.Graph()
    
    # Core nodes
    user_node = f"User {tx_details['sender_id']}"
    device_node = f"Device: {tx_details['device_id']}"
    receiver_node = f"Receiver: {tx_details['receiver_name']}"
    ip_node = f"IP: {tx_details['ip_address']}"
    
    G.add_node(user_node, category="user")
    G.add_node(device_node, category="device")
    G.add_node(receiver_node, category="receiver")
    G.add_node(ip_node, category="ip")
    
    # Establish edges
    G.add_edge(user_node, device_node)
    G.add_edge(user_node, receiver_node)
    G.add_edge(user_node, ip_node)
    
    # Map color scheme
    color_map = []
    patterns_text = " ".join(graph_details.get("detected_patterns", [])).lower()
    
    for node in G.nodes():
        node_cat = G.nodes[node]["category"]
        if node_cat == "user":
            color_map.append("#1f77b4")  # Safe blue for user
        elif node_cat == "device" and ("device" in patterns_text or "compromised" in tx_details['device_id'].lower()):
            color_map.append("#d62728")  # Flagged red
        elif node_cat == "receiver" and ("receiver" in patterns_text or "blacklist" in tx_details['receiver_name'].lower()):
            color_map.append("#d62728")  # Flagged red
        elif node_cat == "ip" and ("ip" in patterns_text or "blacklist" in tx_details['ip_address'].lower()):
            color_map.append("#d62728")  # Flagged red
        else:
            color_map.append("#2ca02c")  # Safe green for others
            
    fig, ax = plt.subplots(figsize=(6, 3.5))
    pos = nx.shell_layout(G)
    
    nx.draw(
        G, pos, with_labels=True, node_color=color_map,
        node_size=1500, font_size=8, font_weight="bold",
        edge_color="#aaaaaa", width=2, ax=ax
    )
    # Set background color to match dashboard layout
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#ffffff')
    plt.tight_layout()
    return fig

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
            st.markdown("Select a transaction below to run a deep-dive security audit.")
            
            # Map review transactions to dictionary
            review_options = {
                f"ID #{t['id']} | User {t['sender_id']} to {t['receiver_name']} (₹{t['amount']:,}) - Score: {t.get('aggregated_score', 'N/A')}": t
                for t in review_queue
            }
            
            selected_tx_label = st.selectbox("Select Transaction to Inspect", list(review_options.keys()))
            
            if selected_tx_label:
                selected_tx = review_options[selected_tx_label]
                st.markdown("---")
                
                # Fetch detailed evaluation
                try:
                    with st.spinner("Fetching full risk evaluation report..."):
                        evaluation = api_client.get_transaction_evaluation(token, selected_tx["id"])
                except Exception as e:
                    st.error(f"Failed to fetch evaluation details: {e}")
                    return

                col_left, col_right = st.columns([1, 1])
                
                with col_left:
                    st.markdown("#### Transaction Metadata")
                    df_meta = pd.DataFrame([
                        {"Attribute": "Transaction ID", "Value": str(selected_tx["id"])},
                        {"Attribute": "Sender ID", "Value": str(selected_tx["sender_id"])},
                        {"Attribute": "Receiver Name", "Value": selected_tx["receiver_name"]},
                        {"Attribute": "Amount", "Value": f"₹{selected_tx['amount']:,}"},
                        {"Attribute": "Device ID", "Value": selected_tx["device_id"]},
                        {"Attribute": "City / Location", "Value": selected_tx["city"]},
                        {"Attribute": "IP Address", "Value": selected_tx["ip_address"]},
                        {"Attribute": "Merchant Category", "Value": selected_tx["merchant_category"]},
                        {"Attribute": "Country", "Value": selected_tx["country"]},
                        {"Attribute": "Submitted At", "Value": datetime.fromisoformat(selected_tx["created_at"]).strftime("%Y-%m-%d %H:%M") if "created_at" in selected_tx else "N/A"},
                    ])
                    st.dataframe(df_meta, hide_index=True, use_container_width=True)

                    # Dynamic score card
                    score = evaluation.get("aggregated_score", 0.0)
                    st.markdown("#### Risk Score Aggregation")
                    if score >= 80.0:
                        st.error(f"Aggregated Score: **{score}/100** (CRITICAL RISK)")
                    elif score >= 38.0:
                        st.warning(f"Aggregated Score: **{score}/100** (MEDIUM RISK)")
                    else:
                        st.success(f"Aggregated Score: **{score}/100** (LOW RISK)")
                    
                    st.info(f"System Confidence: {evaluation.get('confidence', 0.5) * 100:.0f}%")

                with col_right:
                    st.markdown("#### Rule Engine Trigger Status")
                    for rule in evaluation.get("triggered_rules", []):
                        if rule.get("triggered", False):
                            st.markdown(f"**{rule.get('rule_name')}** (+{rule.get('score_contribution')}): {rule.get('reason')}")
                        else:
                            st.markdown(f"*{rule.get('rule_name')}* (Safe): {rule.get('reason')}")

                # deep dive sections
                st.markdown("---")
                st.markdown("### Multi-Engine Deep Dive Audit")
                
                col_ml, col_graph = st.columns(2)
                
                with col_ml:
                    st.markdown("#### ML Anomaly Profiler (Isolation Forest)")
                    ml_details = evaluation.get("ml_details", {})
                    st.metric("ML Anomaly Score", f"{ml_details.get('anomaly_score', 0.0)}/100")
                    
                    # Plot feature contributions
                    contribs = ml_details.get("feature_contributions", {})
                    if contribs:
                        df_contribs = pd.DataFrame([
                            {"Feature": feat.replace("_", " ").title(), "Contribution": weight * 100}
                            for feat, weight in contribs.items()
                        ])
                        fig = px.bar(
                            df_contribs, x="Contribution", y="Feature", orientation="h",
                            title="ML Anomaly Feature Importances (%)",
                            color_discrete_sequence=["#1f77b4"]
                        )
                        fig.update_layout(height=200, margin=dict(l=0, r=0, t=30, b=0))
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info("No feature contributions available.")

                with col_graph:
                    st.markdown("#### Graph Relationship Network (NetworkX)")
                    graph_details = evaluation.get("graph_details", {})
                    st.metric("Graph Risk Score", f"{graph_details.get('risk_score', 0.0)}/100")
                    
                    # Draw graph diagram
                    fig_graph = draw_network_graph(selected_tx, graph_details)
                    st.pyplot(fig_graph)
                    
                    for pattern in graph_details.get("detected_patterns", []):
                        st.warning(f"Pattern Alert: {pattern}")

                # AI Explanations Display
                st.markdown("---")
                st.markdown("#### AI/LLM Security Explanations")
                col_cust_exp, col_analyst_exp = st.columns(2)
                with col_cust_exp:
                    st.info(f"Customer-Facing Explanation:\n\n\"{evaluation.get('customer_explanation', 'N/A')}\"")
                with col_analyst_exp:
                    st.info(f"Investigator-Facing explanation:\n\n{evaluation.get('analyst_explanation', 'N/A')}")

                # Analyst Decision Input
                st.markdown("---")
                st.markdown("#### Record Final Investigation Resolution")
                
                with st.form("decision_form"):
                    notes = st.text_area("Resolution Audit Notes", placeholder="Provide rationale for override action (e.g. verified phone credentials)...")
                    
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
