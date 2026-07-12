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

                # 2. Risk Scoring & Security Rules
                col_left, col_right = st.columns([1, 1])
                
                with col_left:
                    with st.container(border=True):
                        st.markdown("#### Risk Score Aggregation")
                        score = evaluation.get("aggregated_score", 0.0)
                        if score >= 80.0:
                            st.error(f"Aggregated Score: **{score}/100** (CRITICAL RISK)")
                        elif score >= 38.0:
                            st.warning(f"Aggregated Score: **{score}/100** (MEDIUM RISK)")
                        else:
                            st.success(f"Aggregated Score: **{score}/100** (LOW RISK)")
                        
                        st.info(f"System Confidence: {evaluation.get('confidence', 0.5) * 100:.0f}%")
                
                with col_right:
                    with st.container(border=True):
                        st.markdown("#### Triggered Security Rules")
                        
                        # Build a clean dataframe of rules
                        rules_data = []
                        for rule in evaluation.get("triggered_rules", []):
                            status_str = "Triggered" if rule.get("triggered", False) else "Safe"
                            contrib_val = f"+{rule.get('score_contribution')}" if rule.get("triggered", False) else "0.0"
                            rules_data.append({
                                "Rule Name": rule.get("rule_name"),
                                "Status": status_str,
                                "Risk Contrib": contrib_val,
                                "Findings / Rationale": rule.get("reason")
                            })
                        
                        if rules_data:
                            st.dataframe(pd.DataFrame(rules_data), use_container_width=True, hide_index=True)
                        else:
                            st.info("No security rules triggered.")

                # 3. Engine Diagnostics Audits
                st.markdown("### Engine Diagnostics Audits")
                col_ml, col_graph = st.columns(2)
                
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
                        
                        for pattern in graph_details.get("detected_patterns", []):
                            st.warning(f"Connection Pattern: {pattern}")

                # 4. AI/LLM Security Explanations
                st.markdown("### AI Generative Explanations")
                with st.container(border=True):
                    col_cust_exp, col_analyst_exp = st.columns(2)
                    with col_cust_exp:
                        st.info(f"**Customer-Facing Security Notice**:\n\n\"{evaluation.get('customer_explanation', 'N/A')}\"")
                    with col_analyst_exp:
                        st.info(f"**Investigator Security Analysis Summary**:\n\n{evaluation.get('analyst_explanation', 'N/A')}")

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
