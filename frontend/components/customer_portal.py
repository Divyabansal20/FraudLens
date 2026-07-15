import streamlit as st
import pandas as pd
from datetime import datetime
from utils.api_client import api_client

def render_customer_portal(token: str, user_profile: dict):
    st.subheader(f"Welcome back, {user_profile.get('name', 'Customer')}")
    st.markdown("Use this portal to simulate payments and monitor your transaction safety status.")

    # Create tabs
    tab_simulator, tab_history = st.tabs(["Simulate Payment", "Transaction History"])

    with tab_simulator:
        st.markdown("### Transaction Simulator")
        st.markdown("Fill in the fields below to submit a simulated payment to our fraud engine.")

        # Preset options for easy testing
        with st.form("payment_form"):
            col1, col2 = st.columns(2)
            with col1:
                receiver_name = st.text_input("Receiver Name", placeholder="e.g. Amit Patel")
                amount = st.number_input("Amount (INR)", min_value=1.0, value=2000.0, step=100.0)
                payment_method = st.selectbox("Payment Method", ["UPI", "NetBanking", "Credit Card", "Debit Card"])
                merchant_category = st.selectbox("Merchant Category", ["retail", "electronics", "entertainment", "travel", "services"])
            
            with col2:
                device_id = st.text_input("Device ID", value="Samsung_S24_D998", help="A unique ID for the transacting device.")
                city = st.text_input("City", value="Delhi", help="City where the transaction is initiated.")
                ip_address = st.text_input("IP Address", value="192.168.1.10")
                country = st.text_input("Country Code (2 letters)", value="IN", max_chars=2)

            submitted = st.form_submit_button("Submit Secure Payment", use_container_width=True)

            if submitted:
                if not receiver_name or not device_id or not city or not ip_address:
                    st.error("Please fill in all transaction fields.")
                else:
                    payload = {
                        "receiver_name": receiver_name,
                        "amount": float(amount),
                        "payment_method": payment_method,
                        "device_id": device_id,
                        "city": city,
                        "ip_address": ip_address,
                        "merchant_category": merchant_category,
                        "country": country.upper()
                    }
                    
                    try:
                        with st.spinner("Processing transaction through FraudLens engines..."):
                            response = api_client.create_transaction(token, payload)
                            
                        if response.status_code == 200:
                            res_json = response.json()
                            status_val = res_json.get("status")
                            tx_id = res_json.get("id")
                            
                            if status_val == "APPROVED":
                                st.success(f"Transaction #{tx_id} Approved Successfully!")
                                st.balloons()
                            elif status_val == "REVIEW":
                                st.warning(f"Transaction #{tx_id} Held under Review by FraudLens security.")
                                st.info("Verification Required: The payment is temporarily held. An analyst will review this shortly.")
                            elif status_val == "BLOCKED":
                                st.error(f"Transaction #{tx_id} Blocked by FraudLens Security.")
                                st.error(f"Reason: {res_json.get('customer_explanation', 'This payment exhibits high fraud indicators and was suspended to protect your account.')}")
                        else:
                            st.error(f"API Error ({response.status_code}): {response.text}")
                    except Exception as e:
                        st.error(f"Network error communicating with backend: {e}")

    with tab_history:
        st.markdown("### Your Transaction Logs")
        
        try:
            txs = api_client.get_transactions(token)
            if not txs:
                st.info("No transaction history found on this profile.")
            else:
                # Prepare dataframe representation
                df_data = []
                for t in txs:
                    # Clean up timestamps
                    try:
                        dt = datetime.fromisoformat(t["created_at"]).strftime("%Y-%m-%d %H:%M")
                    except:
                        dt = t["created_at"]
                        
                    df_data.append({
                        "ID": t["id"],
                        "Receiver": t["receiver_name"],
                        "Amount (INR)": f"₹{t['amount']:,}",
                        "Method": t["payment_method"],
                        "City": t["city"],
                        "Device ID": t["device_id"],
                        "Status": t["status"],
                        "Date": dt
                    })
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Dynamic inspection cards
                st.markdown("### Inspect Transaction Evaluations")
                st.markdown("Select a transaction from the dropdown below to view the customer security explanation.")
                
                tx_options = {f"ID #{t['id']} to {t['receiver_name']} (INR {t['amount']})": t for t in txs}
                selected_tx_label = st.selectbox("Select Transaction to Inspect", list(tx_options.keys()))
                
                if selected_tx_label:
                    selected_tx = tx_options[selected_tx_label]
                    
                    st.markdown("---")
                    with st.container(border=True):
                        st.markdown(f"#### Evaluation Audit for Transaction #{selected_tx['id']}")
                        
                        # Status styling
                        status_val = selected_tx["status"]
                        if status_val == "APPROVED":
                            st.markdown(f"**Security Decision**: :green[APPROVED]")
                        elif status_val == "REVIEW":
                            st.markdown(f"**Security Decision**: :orange[UNDER REVIEW]")
                        elif status_val == "BLOCKED":
                            st.markdown(f"**Security Decision**: :red[BLOCKED / SUSPENDED]")
                        
                        st.info(f"**Security Alert & Advice**:\n\n{selected_tx.get('customer_explanation', 'Your payment was verified through our multi-stage AI fraud scoring pipeline and cleared for execution.')}")
                        
                        if status_val in ["REVIEW", "BLOCKED"]:
                            st.error("Did you not initiate this payment? Let us know immediately.")
                            report_clicked = st.button("Report: This Wasn't Me", key=f"report_{selected_tx['id']}")
                            if report_clicked:
                                st.toast("Security alert sent to fraud response team! Your account holds have been updated.")
                                st.success("Feedback recorded. An investigator has been assigned to lock this device profile.")
                            
        except Exception as e:
            st.error(f"Error fetching logs: {e}")
