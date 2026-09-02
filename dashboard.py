import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import json
import io
from typing import List, Dict, Optional
from main import PhishingEmailAnalyzer, emails_from_dataframe, IOCExtractor, CampaignHistory
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from pyvis.network import Network
st.set_page_config(page_title='VECTPHISH — Detect phishing campaigns beyond signatures', page_icon='🔒', layout='wide', initial_sidebar_state='expanded')
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = None
if 'campaigns' not in st.session_state:
    st.session_state.campaigns = []
if 'emails' not in st.session_state:
    st.session_state.emails = []
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False

def create_campaign_timeline(campaigns: List[Dict]) -> go.Figure:
    timeline_data = []
    for campaign in campaigns:
        date_range = campaign.get('date_range', ('Unknown', 'Unknown'))
        first_seen = date_range[0]
        last_seen = date_range[1]
        if first_seen != 'Unknown' and last_seen != 'Unknown':
            try:
                first = pd.to_datetime(first_seen)
                last = pd.to_datetime(last_seen)
                timeline_data.append({'Campaign': campaign.get('campaign_name', 'Unknown'), 'First Seen': first, 'Last Seen': last, 'Email Count': campaign.get('email_count', 0), 'Confidence': campaign.get('confidence', 0), 'Campaign ID': campaign.get('campaign_id', 'N/A')})
            except:
                pass
    if not timeline_data:
        return None
    df_timeline = pd.DataFrame(timeline_data)
    fig = go.Figure()
    for idx, row in df_timeline.iterrows():
        fig.add_trace(go.Scatter(x=[row['First Seen'], row['Last Seen']], y=[row['Campaign'], row['Campaign']], mode='lines+markers', name=row['Campaign'], line=dict(width=row['Email Count'] / 5, color=f"hsl({row['Confidence'] * 2.4}, 70%, 50%)"), marker=dict(size=10), hovertemplate=f"<b>{row['Campaign']}</b><br>" + f"First: {row['First Seen'].strftime('%Y-%m-%d')}<br>" + f"Last: {row['Last Seen'].strftime('%Y-%m-%d')}<br>" + f"Emails: {row['Email Count']}<br>" + f"Confidence: {row['Confidence']:.1f}%<extra></extra>"))
    fig.update_layout(title='Campaign Timeline (First Seen → Last Seen)', xaxis_title='Date', yaxis_title='Campaign', height=400, hovermode='closest')
    return fig

def create_volume_chart(campaigns: List[Dict]) -> go.Figure:
    volume_data = []
    for campaign in campaigns:
        date_range = campaign.get('date_range', ('Unknown', 'Unknown'))
        email_count = campaign.get('email_count', 0)
        if date_range[0] != 'Unknown':
            try:
                date = pd.to_datetime(date_range[0])
                volume_data.append({'Date': date, 'Email Count': email_count, 'Campaign': campaign.get('campaign_name', 'Unknown')})
            except:
                pass
    if not volume_data:
        return None
    df_volume = pd.DataFrame(volume_data)
    df_volume = df_volume.groupby(['Date', 'Campaign'])['Email Count'].sum().reset_index()
    fig = px.bar(df_volume, x='Date', y='Email Count', color='Campaign', title='Email Volume by Campaign', labels={'Email Count': 'Number of Emails', 'Date': 'Date'}, height=300)
    return fig

def create_network_graph(campaigns: List[Dict]) -> Network:
    G = nx.Graph()
    for campaign in campaigns:
        campaign_id = f"Campaign_{campaign.get('campaign_id', campaign.get('cluster_id', 'Unknown'))}"
        campaign_name = campaign.get('campaign_name', 'Unknown')
        G.add_node(campaign_id, label=campaign_name, type='campaign', size=20, color='#FF6B6B')
        campaign_data = campaign.get('campaign_data', {})
        iocs = campaign.get('iocs', {})
        for domain in iocs.get('sender_domains', [])[:10]:
            G.add_node(domain, label=domain, type='sender_domain', size=10, color='#4ECDC4')
            G.add_edge(campaign_id, domain, weight=1)
        for domain in iocs.get('url_domains', [])[:10]:
            if domain not in G.nodes():
                G.add_node(domain, label=domain, type='url_domain', size=10, color='#95E1D3')
            G.add_edge(campaign_id, domain, weight=1)
    net = Network(height='600px', width='100%', bgcolor='#222222', font_color='white')
    net.from_nx(G)
    net.set_options('\n    {\n      "physics": {\n        "enabled": true,\n        "stabilization": {"enabled": true, "iterations": 100},\n        "barnesHut": {\n          "gravitationalConstant": -2000,\n          "centralGravity": 0.1,\n          "springLength": 200,\n          "springConstant": 0.05\n        }\n      }\n    }\n    ')
    return net

def export_iocs_formats(iocs: Dict, campaign_name: str):
    col1, col2, col3 = st.columns(3)
    with col1:
        json_str = json.dumps(iocs, indent=2)
        st.download_button(label='📥 Download JSON', data=json_str, file_name=f"iocs_{campaign_name.replace(' ', '_')}.json", mime='application/json')
    with col2:
        csv_rows = []
        for domain in iocs.get('sender_domains', []):
            csv_rows.append({'type': 'sender_domain', 'value': domain})
        for domain in iocs.get('url_domains', []):
            csv_rows.append({'type': 'url_domain', 'value': domain})
        for path in iocs.get('url_paths', []):
            csv_rows.append({'type': 'url_path', 'value': path})
        df_csv = pd.DataFrame(csv_rows)
        csv_str = df_csv.to_csv(index=False)
        st.download_button(label='📥 Download CSV', data=csv_str, file_name=f"iocs_{campaign_name.replace(' ', '_')}.csv", mime='text/csv')
    with col3:
        sigma_rules = []
        if iocs.get('sender_domains'):
            domains_str = '|'.join(iocs['sender_domains'])
            sigma_rules.append(f'SenderDomain|contains|{domains_str}')
        if iocs.get('url_domains'):
            domains_str = '|'.join(iocs['url_domains'])
            sigma_rules.append(f'UrlDomain|contains|{domains_str}')
        sigma_content = f"title: Phishing Campaign IOCs - {campaign_name}\ndescription: Auto-extracted IOCs from phishing campaign analysis\nlogsource:\n    product: email\ndetection:\n    selection:\n        {chr(10).join(('        ' + rule for rule in sigma_rules))}\n    condition: selection\nlevel: high\n"
        st.download_button(label='📥 Download Sigma', data=sigma_content, file_name=f"iocs_{campaign_name.replace(' ', '_')}_sigma.yml", mime='text/yaml')

def main():
    st.title('🔒 VECTPHISH — Detect phishing campaigns beyond signatures')
    st.markdown('****')
    with st.sidebar:
        st.header('📤 Data Input')
        uploaded_file = st.file_uploader('Upload CSV file', type=['csv'], help='CSV: SenderFromAddress, Subject, TimeGenerated, Url, NetworkMessageId (Sentinel export)')
        use_sample = st.checkbox('Use sample data', value=False)
        st.header('🔍 Correlation Input')
        st.markdown('**Enter ONE input to find similar emails:**')
        input_type = st.radio('Input Type', ['sender', 'subject', 'url'], help='Select what type of input you want to search by')
        user_input = st.text_input(f'Enter {input_type}', placeholder=f'security@fake-bank.com' if input_type == 'sender' else f'URGENT: Verify your account' if input_type == 'subject' else f'https://fake-bank.com/login', help=f'Enter the {input_type} to search for similar emails')
        st.header('⚙️ Analysis Parameters')
        similarity_threshold = st.slider('Similarity Threshold (for email search)', 0.3, 0.9, 0.5, 0.1)
        recurrence_threshold = st.slider('Recurrence Threshold', 0.7, 0.95, 0.85, 0.05, help='Threshold for matching historical campaigns (higher = stricter)')
        eps = st.slider('DBSCAN Eps', 0.3, 0.8, 0.5, 0.1)
        min_samples = st.slider('Min Samples', 1, 5, 2, 1)
        enable_history = st.checkbox('Enable Campaign History', value=True)
        if st.button('🚀 Run Analysis', type='primary', use_container_width=True):
            if not user_input or not user_input.strip():
                st.error('❌ Please enter a value for the selected input type')
                st.stop()
            if uploaded_file is None and (not use_sample):
                st.error('❌ Please upload a CSV file or use sample data')
                st.stop()
            with st.spinner('Loading analyzer and processing emails...'):
                try:
                    st.session_state.analyzer = PhishingEmailAnalyzer(enable_history=enable_history)
                    if uploaded_file is not None:
                        df = pd.read_csv(uploaded_file)
                        st.session_state.all_emails = emails_from_dataframe(df)
                    elif use_sample:
                        from main import create_sample_data
                        st.session_state.all_emails = create_sample_data()
                    st.info(f'📊 Loaded {len(st.session_state.all_emails)} emails from dataset')
                    with st.spinner(f'🔍 Searching for emails similar to {input_type}: {user_input[:50]}...'):
                        similar_emails = st.session_state.analyzer.find_similar_emails(user_input=user_input.strip(), input_type=input_type, all_emails=st.session_state.all_emails, similarity_threshold=similarity_threshold, max_results=100)
                    if not similar_emails:
                        st.warning(f'⚠️ No similar emails found with similarity threshold {similarity_threshold}. Try lowering the threshold.')
                        st.stop()
                    st.success(f'✅ Found {len(similar_emails)} similar emails')
                    with st.spinner(f'📈 Analyzing {len(similar_emails)} correlated emails...'):
                        st.session_state.emails = similar_emails
                        st.session_state.campaigns = st.session_state.analyzer.analyze(similar_emails, eps=eps, min_samples=min_samples, recurrence_threshold=recurrence_threshold)
                    st.session_state.analysis_complete = True
                    st.session_state.user_input_type = input_type
                    st.session_state.user_input_value = user_input
                    st.success(f'🎉 Analysis complete! Found {len(st.session_state.campaigns)} campaigns from {len(similar_emails)} similar emails')
                except Exception as e:
                    st.error(f'Error: {str(e)}')
                    st.stop()
    if not st.session_state.analysis_complete:
        st.info("👈 **Steps:** 1) Upload CSV or use sample data 2) Select input type (sender/subject/url) 3) Enter value 4) Click 'Run Analysis'")
        if 'all_emails' in st.session_state:
            st.metric('Dataset Size', len(st.session_state.all_emails))
        return
    campaigns = st.session_state.campaigns
    tab1, tab2, tab3, tab4, tab5 = st.tabs(['📊 Campaign Overview', '🤖 LLM Analysis', '📅 Timeline & Recurrence', '🎯 IOC & ATT&CK', '🕸️ Network Graph'])
    with tab1:
        if 'user_input_type' in st.session_state:
            st.info(f'🔍 **Correlation Input:** `{st.session_state.user_input_type}` = `{st.session_state.user_input_value}` → Found {len(st.session_state.emails)} similar emails → {len(campaigns)} campaigns')
        st.header('Campaign Overview')
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            filter_confidence = st.slider('Min Confidence', 0, 100, 0)
        with col2:
            filter_brand = st.selectbox('Brand', ['All'] + list(set([b for c in campaigns for b in c.get('campaign_data', {}).get('detected_brands', [])])))
        with col3:
            filter_attack = st.selectbox('ATT&CK Technique', ['All'] + list(set([t['technique_id'] for c in campaigns for t in c.get('attack_techniques', [])])))
        with col4:
            filter_recurrence = st.selectbox('Recurrence', ['All', 'New', 'Recurrence'])
        filtered_campaigns = campaigns
        if filter_confidence > 0:
            filtered_campaigns = [c for c in filtered_campaigns if c.get('confidence', 0) >= filter_confidence]
        if filter_brand != 'All':
            filtered_campaigns = [c for c in filtered_campaigns if filter_brand in c.get('campaign_data', {}).get('detected_brands', [])]
        if filter_attack != 'All':
            filtered_campaigns = [c for c in filtered_campaigns if any((t['technique_id'] == filter_attack for t in c.get('attack_techniques', [])))]
        if filter_recurrence == 'New':
            filtered_campaigns = [c for c in filtered_campaigns if not c.get('is_recurrence', False)]
        elif filter_recurrence == 'Recurrence':
            filtered_campaigns = [c for c in filtered_campaigns if c.get('is_recurrence', False)]
        st.subheader(f'Campaigns ({len(filtered_campaigns)} found)')
        table_data = []
        for campaign in filtered_campaigns:
            table_data.append({'Campaign': campaign.get('campaign_name', 'Unknown'), 'ID': campaign.get('campaign_id', 'N/A'), 'Emails': campaign.get('email_count', 0), 'Confidence': f"{campaign.get('confidence', 0):.1f}%", 'Date Range': f"{campaign.get('date_range', ('', ''))[0]} to {campaign.get('date_range', ('', ''))[1]}", 'Brands': ', '.join(campaign.get('campaign_data', {}).get('detected_brands', [])[:2]), 'ATT&CK': ', '.join([t['technique_id'] for t in campaign.get('attack_techniques', [])[:2]]), 'Recurrence': '✅' if campaign.get('is_recurrence') else '🆕'})
        df_table = pd.DataFrame(table_data)
        st.dataframe(df_table, use_container_width=True, hide_index=True)
        if filtered_campaigns:
            st.subheader('🔍 Campaign Drill-Down')
            selected_campaign_name = st.selectbox('Select campaign for details', [c.get('campaign_name', 'Unknown') for c in filtered_campaigns])
            selected_campaign = next((c for c in filtered_campaigns if c.get('campaign_name') == selected_campaign_name), None)
            if selected_campaign:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown('### Campaign Details')
                    st.write(f"**Campaign ID:** {selected_campaign.get('campaign_id', 'N/A')}")
                    st.write(f"**Emails:** {selected_campaign.get('email_count', 0)}")
                    st.write(f"**Confidence:** {selected_campaign.get('confidence', 0):.1f}%")
                    st.write(f"**Date Range:** {selected_campaign.get('date_range', ('', ''))[0]} to {selected_campaign.get('date_range', ('', ''))[1]}")
                    if selected_campaign.get('is_recurrence'):
                        rec_info = selected_campaign.get('recurrence_info', {})
                        st.write(f"**Recurrence:** ✅ Similarity {rec_info.get('similarity', 0):.2%}")
                        st.write(f"**First Seen:** {rec_info.get('first_seen', 'Unknown')}")
                with col2:
                    st.markdown('### Top Indicators')
                    campaign_data = selected_campaign.get('campaign_data', {})
                    st.write('**Top Subjects:**')
                    for subject in campaign_data.get('sample_subjects', [])[:3]:
                        st.write(f'- {subject[:60]}...')
                    st.write('**Top URLs:**')
                    for url in campaign_data.get('sample_urls', [])[:3]:
                        st.write(f'- {url[:60]}...')
                    st.write(f"**Urgency Score:** {campaign_data.get('urgency_keyword_usage', 0)} emails")
    with tab2:
        st.header('🤖 LLM-Generated Analysis')
        st.markdown('**AI-powered threat intelligence and campaign insights generated by Ollama LLM**')
        if not campaigns:
            st.info('No campaigns to display')
            return
        selected_campaign_idx = st.selectbox('Select Campaign', range(len(campaigns)), format_func=lambda x: f"{campaigns[x].get('campaign_name', 'Unknown')} (ID: {campaigns[x].get('campaign_id', 'N/A')})")
        selected_campaign = campaigns[selected_campaign_idx]
        st.markdown('---')
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader('📝 Campaign Name (LLM Generated)')
            st.info(f"**{selected_campaign.get('campaign_name', 'Unknown')}**")
            st.subheader('🎯 Threat Intelligence')
            threat_intel = selected_campaign.get('threat_intelligence', '')
            if threat_intel:
                st.text_area('LLM Analysis', threat_intel, height=200, disabled=True, label_visibility='collapsed')
            else:
                st.warning('No threat intelligence available')
            st.subheader('🔗 Correlation Logic')
            correlation = selected_campaign.get('correlation_logic', '')
            if correlation:
                st.text_area('LLM Explanation', correlation, height=150, disabled=True, label_visibility='collapsed')
            else:
                st.info('Correlation logic not available')
        with col2:
            st.subheader('📊 Campaign Stats')
            st.metric('Emails', selected_campaign.get('email_count', 0))
            st.metric('Confidence', f"{selected_campaign.get('confidence', 0):.1f}%")
            st.metric('Date Range', f"{selected_campaign.get('date_range', ('', ''))[0]}")
            if selected_campaign.get('is_recurrence'):
                st.success('🔄 Recurring Campaign')
                rec_info = selected_campaign.get('recurrence_info', {})
                st.write(f"Similarity: {rec_info.get('similarity', 0):.2%}")
            else:
                st.info('🆕 New Campaign')
        st.markdown('---')
        st.subheader('🛡️ Recommended Mitigation Steps (LLM Generated)')
        mitigation_steps = selected_campaign.get('mitigation_steps', [])
        if mitigation_steps:
            for i, step in enumerate(mitigation_steps, 1):
                st.write(f'{i}. {step}')
        else:
            st.info('No mitigation steps available')
        with st.expander('🔍 View Raw LLM Response Data'):
            llm_data = {'campaign_name': selected_campaign.get('campaign_name'), 'threat_intelligence': selected_campaign.get('threat_intelligence'), 'correlation_logic': selected_campaign.get('correlation_logic'), 'mitigation_steps': selected_campaign.get('mitigation_steps')}
            st.json(llm_data)
    with tab3:
        st.header('Campaign Timeline & Recurrence Analysis')
        col1, col2 = st.columns(2)
        with col1:
            st.subheader('📅 Campaign Timeline')
            timeline_fig = create_campaign_timeline(campaigns)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
            else:
                st.info('No timeline data available')
        with col2:
            st.subheader('📈 Volume Spikes')
            volume_fig = create_volume_chart(campaigns)
            if volume_fig:
                st.plotly_chart(volume_fig, use_container_width=True)
            else:
                st.info('No volume data available')
        st.subheader('🔄 Recurrence Panel')
        recurrence_campaigns = [c for c in campaigns if c.get('is_recurrence')]
        new_campaigns = [c for c in campaigns if not c.get('is_recurrence')]
        col1, col2 = st.columns(2)
        with col1:
            st.metric('Recurring Campaigns', len(recurrence_campaigns))
            if recurrence_campaigns:
                for campaign in recurrence_campaigns:
                    rec_info = campaign.get('recurrence_info', {})
                    with st.expander(f"🔁 {campaign.get('campaign_name', 'Unknown')}"):
                        st.write(f"**Similarity:** {rec_info.get('similarity', 0):.2%}")
                        st.write(f"**First Seen:** {rec_info.get('first_seen', 'Unknown')}")
                        st.write(f"**Last Seen:** {rec_info.get('last_seen', 'Unknown')}")
                        st.write(f"**Historical Email Count:** {rec_info.get('email_count', 0)}")
                        st.write(f"**Current Email Count:** {campaign.get('email_count', 0)}")
        with col2:
            st.metric('New Campaigns', len(new_campaigns))
            if new_campaigns:
                for campaign in new_campaigns:
                    with st.expander(f"🆕 {campaign.get('campaign_name', 'Unknown')}"):
                        st.write(f"**Campaign ID:** {campaign.get('campaign_id', 'N/A')}")
                        st.write(f"**Emails:** {campaign.get('email_count', 0)}")
                        st.write(f"**Confidence:** {campaign.get('confidence', 0):.1f}%")
    with tab4:
        st.header('IOC & ATT&CK Analysis')
        if not campaigns:
            st.info('No campaigns to display')
            return
        selected_campaign_idx = st.selectbox('Select Campaign', range(len(campaigns)), format_func=lambda x: campaigns[x].get('campaign_name', 'Unknown'))
        selected_campaign = campaigns[selected_campaign_idx]
        col1, col2 = st.columns(2)
        with col1:
            st.subheader('🎯 Extracted IOCs')
            iocs = selected_campaign.get('iocs', {})
            st.write(f"**Sender Domains:** {len(iocs.get('sender_domains', []))}")
            if iocs.get('sender_domains'):
                st.dataframe(pd.DataFrame({'Domain': iocs['sender_domains']}), use_container_width=True, hide_index=True)
            st.write(f"**URL Domains:** {len(iocs.get('url_domains', []))}")
            if iocs.get('url_domains'):
                st.dataframe(pd.DataFrame({'Domain': iocs['url_domains']}), use_container_width=True, hide_index=True)
            st.write(f"**URL Paths:** {len(iocs.get('url_paths', []))}")
            if iocs.get('url_paths'):
                st.dataframe(pd.DataFrame({'Path': iocs['url_paths']}), use_container_width=True, hide_index=True)
            st.markdown('---')
            export_iocs_formats(iocs, selected_campaign.get('campaign_name', 'campaign'))
        with col2:
            st.subheader('⚔️ MITRE ATT&CK Techniques')
            attack_techniques = selected_campaign.get('attack_techniques', [])
            if attack_techniques:
                for tech in attack_techniques:
                    with st.expander(f"{tech['technique_id']}: {tech['technique_name']} (Confidence: {tech['confidence']:.0%})"):
                        st.write(f"**Rationale:** {tech['rationale']}")
            else:
                st.info('No ATT&CK techniques identified')
    with tab5:
        st.header('🕸️ Campaign Relationship Graph')
        st.markdown('**Nodes:** Campaigns (red), Sender Domains (teal), URL Domains (green) | **Edges:** Relationships')
        if campaigns:
            net = create_network_graph(campaigns)
            net.save_graph('network_graph.html')
            HtmlFile = open('network_graph.html', 'r', encoding='utf-8')
            source_code = HtmlFile.read()
            st.components.v1.html(source_code, height=600)
        else:
            st.info('No campaigns to visualize')
if __name__ == '__main__':
    main()
