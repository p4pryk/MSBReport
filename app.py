import streamlit as st
import json
from datetime import datetime
import os
from dotenv import load_dotenv
from collections import defaultdict
import pandas as pd

# This must be the first Streamlit command 
st.set_page_config(
    page_title="Azure Security Benchmark Report", 
    layout="wide",
    initial_sidebar_state="expanded"
)

from auth import get_access_token
from graph_api import get_subscriptions, get_security_assessments, get_assessment_details, debug_assessment_structure

# Load environment variables from .env file (if exists)
load_dotenv()

# Load custom CSS
def load_css():
    with open("style.css") as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Custom card component
def card(title, content):
    st.markdown(f"""
    <div class="card">
        <div class="card-title">{title}</div>
        {content}
    </div>
    """, unsafe_allow_html=True)

# Custom metric component
def metric_card(title, value, label="", color=None):
    color_class = f"style='color: {color};'" if color else ""
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" {color_class}>{value}</div>
        <div class="metric-label">{title}</div>
        <div class="metric-sublabel">{label}</div>
    </div>
    """, unsafe_allow_html=True)

# Format status with appropriate styling
def format_status(status):
    if status == "Healthy":
        return f'<span class="status-healthy">●&nbsp;{status}</span>'
    elif status == "Unhealthy":
        return f'<span class="status-unhealthy">●&nbsp;{status}</span>'
    else:
        return status
        
# Format severity with appropriate styling
def format_severity(severity):
    if severity == "High":
        return f'<span class="severity-high">●&nbsp;{severity}</span>'
    elif severity == "Medium":
        return f'<span class="severity-medium">●&nbsp;{severity}</span>'
    elif severity == "Low":
        return f'<span class="severity-low">●&nbsp;{severity}</span>'
    else:
        return severity

# The existing normalize_category function
def normalize_category(category_name):
    """
    Normalize category names to ensure consistent naming across the application
    """
    if not category_name:
        return "Other"
    
    # Simple normalization logic - expand as needed
    category_mapping = {
        "identity": "Identity & Access",
        "access": "Identity & Access",
        "compute": "Virtual Machines",
        "vm": "Virtual Machines",
        "network": "Networking",
        "data": "Data Protection",
        "storage": "Storage",
        "security": "Security Center",
        "key": "Key Management",
        "app": "Applications",
        "web": "Applications",
        "sql": "Databases",
        "database": "Databases",
        "monitor": "Monitoring & Logging",
        "log": "Monitoring & Logging"
    }
    
    # Check for matches in the mapping
    category_lower = category_name.lower()
    for key, mapped_value in category_mapping.items():
        if key in category_lower:
            return mapped_value
            
    return "Other"

# Load custom CSS
load_css()

# Azure logo and page title
st.markdown("""
<div style="display: flex; align-items: center; margin-bottom: 1rem;">
    <img src="https://azure.microsoft.com/svghandler/azure-fundamentals?width=50&height=50" alt="Azure Logo" style="margin-right: 10px;">
    <h1 style="margin: 0;">Generate Security Benchmark Report</h1>
</div>
""", unsafe_allow_html=True)

# Authentication settings
with st.sidebar:
    st.markdown("""
    <div class="sidebar-header">
        <img src="https://azure.microsoft.com/svghandler/azure-fundamentals?width=30&height=30" alt="Azure Logo" style="vertical-align: middle; margin-right: 10px;">
        <span>Azure Authentication</span>
    </div>
    """, unsafe_allow_html=True)
    
    # Add app description
    st.markdown("""
    <div class="sidebar-description">
        <p><strong>Generate Security Benchmark Report</strong> helps you analyze and visualize security recommendations for your Azure resources.</p>
        <p>This application allows you to identify security vulnerabilities and compliance with Microsoft Security Benchmark best practices.</p>
        <div class="app-version">Version 1.0</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Auto-login on startup
    if "login_attempted" not in st.session_state:
        # Get credentials from environment variables
        tenant_id = os.getenv("TENANT_ID", "")
        client_id = os.getenv("CLIENT_ID", "")
        client_secret = os.getenv("CLIENT_SECRET", "")
        
        # Try automatic login if all credentials are available
        if tenant_id and client_id and client_secret:
            with st.spinner("Logging in automatically..."):
                token = get_access_token(tenant_id, client_id, client_secret)
                if token:
                    st.session_state.token = token
                    st.session_state.login_attempted = True
                    st.success("Auto-login successful!")
                else:
                    st.session_state.login_attempted = True
                    st.error("Auto-login failed. Please enter credentials manually.")
        else:
            st.session_state.login_attempted = True
    
    # Show authentication status
    if "token" in st.session_state:
        st.markdown("""
        <div class="login-status-success">
            <span class="status-icon">✓</span> Authenticated
        </div>
        """, unsafe_allow_html=True)
        
        # Add logout option
        if st.button("Logout"):
            del st.session_state.token
            st.rerun()
    else:
        # Show manual login form as fallback
        st.markdown("""
        <div class="login-status-warning">
            <span class="status-icon">!</span> Manual authentication required
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("Manual Login"):
            # Login data - use environment variables as default values
            tenant_id = st.text_input("Tenant ID", value=os.getenv("TENANT_ID", ""), type="password")
            client_id = st.text_input("Client ID (App ID)", value=os.getenv("CLIENT_ID", ""), type="password")
            client_secret = st.text_input("Client Secret", value=os.getenv("CLIENT_SECRET", ""), type="password")
            
            login_button = st.button("Login")
            
            if login_button:
                if not tenant_id or not client_id or not client_secret:
                    st.error("All authentication fields are required!")
                else:
                    with st.spinner("Logging in..."):
                        token = get_access_token(tenant_id, client_id, client_secret)
                        if token:
                            st.session_state.token = token
                            st.success("Successfully logged in!")
                        else:
                            st.error("Login error. Check your authentication data.")
    
    # Debug options in sidebar - with unique key
    if st.sidebar.checkbox("Debug mode", key="debug_mode_sidebar"):
        st.session_state.debug = True
        st.markdown("""
        <div class="warning-box">
            Debug mode is enabled - detailed information will be displayed in the console.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.session_state.debug = False
    
    # Add sidebar footer with version info and improved styling - removed duplicate info
    st.sidebar.markdown("---")

# Main interface
if "token" in st.session_state:
    # Get list of subscriptions
    if "subscriptions" not in st.session_state:
        with st.spinner("Loading subscriptions..."):
            subscriptions = get_subscriptions(st.session_state.token)
            st.session_state.subscriptions = subscriptions
    
    # Subscription selection
    if st.session_state.subscriptions:
        subscription_options = {sub['displayName']: sub['subscriptionId'] for sub in st.session_state.subscriptions}
        
        # Create a layout with proper column widths
        col1, col2 = st.columns([3, 1])
        
        # Put subscription dropdown in first column
        with col1:
            selected_subscription_name = st.selectbox(
                "Select Azure Subscription:",
                options=list(subscription_options.keys())
            )
            # Store the selected subscription ID for use in both columns
            selected_subscription_id = subscription_options[selected_subscription_name]
        
        # The second column is now empty, removing the debug analyze button
        
        # Button to get recommendations (full width, outside the columns)
        if st.button("Generate report"):
            with st.spinner("Loading security recommendations..."):
                assessments = get_security_assessments(st.session_state.token, selected_subscription_id, st.session_state.get('debug', False))
                
                if not assessments:
                    st.markdown("""
                    <div class="warning-box">
                        No Microsoft Security Benchmark recommendations found for this subscription.
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    # Filter to show only Unhealthy recommendations
                    unhealthy_assessments = [a for a in assessments if a.get('recommendationState', '') == 'Unhealthy']
                    
                    if not unhealthy_assessments:
                        st.markdown("""
                        <div class="success-box">
                            <strong>All Good!</strong> No unhealthy recommendations found. All security checks passed!
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        # Summary of statuses
                        statuses = {}
                        severities = {"High": 0, "Medium": 0, "Low": 0}
                        
                        for assessment in assessments:
                            # Extract status properly from the assessment object
                            if 'properties' in assessment and 'status' in assessment['properties'] and 'code' in assessment['properties']['status']:
                                status = assessment['properties']['status']['code']
                            else:
                                status = assessment.get('recommendationState', 'Unknown')
                            statuses[status] = statuses.get(status, 0) + 1
                            
                            # Count by severity only for Unhealthy assessments (ignore Not Applicable)
                            if status == 'Unhealthy':
                                severity = assessment.get('recommendationSeverity', 'Unknown')
                                if severity in severities:
                                    severities[severity] += 1
                        
                        # Display dashboard metrics
                        st.markdown("<h2>Security Dashboard</h2>", unsafe_allow_html=True)
                        
                        metric_cols = st.columns(4)
                        with metric_cols[0]:
                            healthy_count = statuses.get('Healthy', 0)
                            # Only count Healthy and Unhealthy for compliance score
                            applicable_count = statuses.get('Healthy', 0) + statuses.get('Unhealthy', 0)
                            total_count = sum(statuses.values())
                            healthy_percent = int((healthy_count / applicable_count) * 100) if applicable_count > 0 else 0
                            metric_card("Compliance Score", f"{healthy_percent}%", f"{healthy_count} of {applicable_count} applicable checks passed", "#107c10")
                        
                        with metric_cols[1]:
                            metric_card("High Severity", severities.get('High', 0), "Issues", "#e81123")
                            
                        with metric_cols[2]:
                            metric_card("Medium Severity", severities.get('Medium', 0), "Issues", "#ffb900")
                            
                        with metric_cols[3]:
                            metric_card("Low Severity", severities.get('Low', 0), "Issues", "#0078d4")
                        
                        # Add spacing between metrics and tabs
                        st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)
                        
                        # Create tabs for different views
                        tabs = st.tabs(["All Recommendations", "By Category"])
                        
                        # Group recommendations by category
                        resource_types = defaultdict(list)
                        
                        for assessment in unhealthy_assessments:
                            # Extract category from the assessment
                            main_category = "Other"
                            
                            # Try to extract category from different fields
                            if isinstance(assessment.get('category'), list) and assessment['category']:
                                main_category = assessment['category'][0]
                            elif 'properties' in assessment and 'metadata' in assessment['properties'] and 'categories' in assessment['properties']['metadata']:
                                categories = assessment['properties']['metadata']['categories']
                                if isinstance(categories, list) and categories:
                                    main_category = categories[0]
                            
                            # Apply normalization to ensure consistent grouping
                            main_category = normalize_category(main_category)
                            resource_types[main_category].append(assessment)
                        
                        # Define severity order for sorting
                        severity_order = {"High": 0, "Medium": 1, "Low": 2}
                        
                        # Tab 1: All Recommendations
                        with tabs[0]:
                            # Prepare data for the table
                            all_assessment_data = []
                            for resource_type, group_assessments in resource_types.items():
                                for assessment in group_assessments:
                                    description = assessment.get('description', 'N/A')
                                    truncated_desc = description[:100] + '...' if description and len(description) > 100 else description
                                    
                                    # Extract status properly from the assessment object
                                    status = 'Unknown'
                                    if 'properties' in assessment and 'status' in assessment['properties'] and 'code' in assessment['properties']['status']:
                                        status = assessment['properties']['status']['code']
                                    elif 'recommendationState' in assessment:
                                        status = assessment['recommendationState']
                                    
                                    # Get severity with proper case handling
                                    severity = assessment.get('recommendationSeverity', 'N/A')
                                    
                                    # Extract affected resource information correctly from the resource structure
                                    affected_resource = "N/A"
                                    
                                    # First check for resourceDetails structure which contains resource information
                                    if 'properties' in assessment and 'resourceDetails' in assessment['properties']:
                                        resource_details = assessment['properties']['resourceDetails']
                                        
                                        # Check if we have ResourceName directly in the structure
                                        if 'ResourceName' in resource_details:
                                            affected_resource = resource_details['ResourceName']
                                        # Also check lowercase variant
                                        elif 'resourceName' in resource_details:
                                            affected_resource = resource_details['resourceName']
                                        # Check for Source property which sometimes contains the resource name
                                        elif 'Source' in resource_details:
                                            affected_resource = resource_details['Source']
                                        
                                        # If we have both resource provider and type but no name, this might indicate multiple resources
                                        if affected_resource == "N/A" and 'ResourceType' in resource_details:
                                            resource_type_name = resource_details['ResourceType'].split('/')[-1]
                                            affected_resource = f"Multiple {resource_type_name} resources"
                                    
                                    all_assessment_data.append({
                                        "Name": assessment.get('recommendationName', 'N/A'),
                                        "Affected Resource": affected_resource,
                                        "Status": status,  
                                        "Severity": severity,  
                                        "Description": truncated_desc
                                    })
                            
                            # Sort by severity (High to Low)
                            severity_order = {"High": 0, "Medium": 1, "Low": 2}
                            sorted_assessments = sorted(
                                all_assessment_data,
                                key=lambda x: severity_order.get(x["Severity"], 999)
                            )
                            
                            # Clean HTML content from the description field
                            for assessment in sorted_assessments:
                                if isinstance(assessment["Description"], str) and ("<a" in assessment["Description"] or "&nbsp;" in assessment["Description"]):
                                    # Remove HTML tags from description
                                    assessment["Description"] = assessment["Description"].replace("</a>", "").replace("&nbsp;", " ")
                                    if "<a" in assessment["Description"]:
                                        assessment["Description"] = assessment["Description"].split("<a")[0]
                            
                            # Convert to DataFrame for streamlit display
                            df = pd.DataFrame(sorted_assessments)
                            
                            # Use Streamlit's native dataframe display with custom styling
                            if not df.empty:
                                # Create custom CSS for coloring cells
                                st.markdown("""
                                <style>
                                .severity-high { color: #e81123 !important; font-weight: bold; }
                                .severity-medium { color: #ffb900 !important; font-weight: bold; }
                                .severity-low { color: #0078d4 !important; font-weight: bold; }
                                .status-healthy { color: #107c10 !important; font-weight: bold; }
                                .status-unhealthy { color: #e81123 !important; font-weight: bold; }
                                </style>
                                """, unsafe_allow_html=True)
                                
                                # Apply styling function to display colored text with proper styling
                                def highlight_severity(val):
                                    if val == 'High':
                                        return 'color: #e81123; font-weight: bold'
                                    elif val == 'Medium':
                                        return 'color: #ffb900; font-weight: bold'
                                    elif val == 'Low':
                                        return 'color: #0078d4; font-weight: bold'
                                    return ''
                                
                                def highlight_status(val):
                                    # Don't apply any styling since all items are Unhealthy
                                    return ''
                                    
                                # Apply styler - we only style the Severity column now
                                styled_df = df.style.map(highlight_severity, subset=['Severity'])
                                
                                # Display with Streamlit's native table
                                st.markdown('<div class="dataframe-container">', unsafe_allow_html=True)
                                st.dataframe(styled_df, use_container_width=True, height=450)
                                st.markdown('</div>', unsafe_allow_html=True)
                            else:
                                st.info("No recommendations to display.")

                        # Tab 2: By Category
                        with tabs[1]:
                            for category, assessments in resource_types.items():
                                with st.expander(f"{category} ({len(assessments)})", expanded=True if len(assessments) > 0 and category in ["Identity & Access", "Virtual Machines"] else False):
                                    category_data = []
                                    for assessment in assessments:
                                        description = assessment.get('description', 'N/A')
                                        truncated_desc = description[:100] + '...' if description and len(description) > 100 else description
                                        
                                        status = 'Unknown'
                                        if 'properties' in assessment and 'status' in assessment['properties'] and 'code' in assessment['properties']['status']:
                                            status = assessment['properties']['status']['code']
                                        elif 'recommendationState' in assessment:
                                            status = assessment['recommendationState']
                                        
                                        severity = assessment.get('recommendationSeverity', 'N/A')
                                        
                                        # Extract affected resource information correctly from the resource structure
                                        affected_resource = "N/A"
                                        
                                        # First check for resourceDetails structure which contains resource information
                                        if 'properties' in assessment and 'resourceDetails' in assessment['properties']:
                                            resource_details = assessment['properties']['resourceDetails']
                                            
                                            # Check if we have ResourceName directly in the structure
                                            if 'ResourceName' in resource_details:
                                                affected_resource = resource_details['ResourceName']
                                            # Also check lowercase variant
                                            elif 'resourceName' in resource_details:
                                                affected_resource = resource_details['resourceName']
                                            # Check for Source property which sometimes contains the resource name
                                            elif 'Source' in resource_details:
                                                affected_resource = resource_details['Source']
                                            
                                            # If we have both resource provider and type but no name, this might indicate multiple resources
                                            if affected_resource == "N/A" and 'ResourceType' in resource_details:
                                                resource_type_name = resource_details['ResourceType'].split('/')[-1]
                                                affected_resource = f"Multiple {resource_type_name} resources"
                                        
                                        category_data.append({
                                            "Name": assessment.get('recommendationName', 'N/A'),
                                            "Affected Resource": affected_resource,
                                            "Status": status,
                                            "Severity": severity,
                                            "Description": truncated_desc
                                        })
                                    
                                    # Sort by severity within each category
                                    sorted_category = sorted(
                                        category_data,
                                        key=lambda x: severity_order.get(x["Severity"], 999)
                                    )
                                    
                                    # Clean HTML content from the description field
                                    for item in sorted_category:
                                        if isinstance(item["Description"], str) and ("<a" in item["Description"] or "&nbsp;" in item["Description"]):
                                            # Remove HTML tags from description
                                            item["Description"] = item["Description"].replace("</a>", "").replace("&nbsp;", " ")
                                            if "<a" in item["Description"]:
                                                item["Description"] = item["Description"].split("<a")[0]
                                    
                                    # Convert to DataFrame for streamlit display
                                    category_df = pd.DataFrame(sorted_category)
                                    
                                    if not category_df.empty:
                                        # Apply styling function to display colored text with proper styling
                                        def highlight_severity(val):
                                            if val == 'High':
                                                return 'color: #e81123; font-weight: bold'
                                            elif val == 'Medium':
                                                return 'color: #ffb900; font-weight: bold'
                                            elif val == 'Low':
                                                return 'color: #0078d4; font-weight: bold'
                                            return ''
                                        
                                        # Apply styler - we only style the Severity column now
                                        styled_category_df = category_df.style.map(highlight_severity, subset=['Severity'])
                                        
                                        # Display with Streamlit's native table
                                        st.dataframe(styled_category_df, use_container_width=True)
                                    else:
                                        st.info(f"No {category} recommendations to display.")

                        # Export options
                        st.markdown("<h3>Export Options</h3>", unsafe_allow_html=True)
                        
                        col1, col2, col3 = st.columns([1, 1, 4])  # Using columns with empty space to center the buttons
                        
                        with col1:
                            if st.button("Export to JSON", key="export_button", use_container_width=True):
                                report = {
                                    "subscription_name": selected_subscription_name,
                                    "subscription_id": selected_subscription_id,
                                    "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "summary": {
                                        "statuses": {status: count for status, count in statuses.items()},
                                        "severities": {severity: count for severity, count in severities.items()},
                                        "compliance_score": healthy_percent
                                    },
                                    "assessments": assessments
                                }
                                
                                # Save report as JSON
                                report_json = json.dumps(report, indent=2)
                                st.download_button(
                                    label="Download JSON Report",
                                    data=report_json,
                                    file_name=f"security_report_{selected_subscription_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json"
                                )
                        
                        with col2:
                            if st.button("Export to CSV", key="export_csv_button", use_container_width=True):
                                # Prepare CSV data from all_assessment_data
                                
                                # Clean HTML from the data
                                csv_data = []
                                for item in all_assessment_data:
                                    clean_item = {}
                                    for k, v in item.items():
                                        if isinstance(v, str) and ("&nbsp;" in v or "<span" in v):
                                            # Extract plain text from HTML tags
                                            if "severity-high" in v or "severity-medium" in v or "severity-low" in v or "status-" in v:
                                                clean_v = v.split(';&nbsp;')[-1].replace('</span>', '')
                                            else:
                                                clean_v = v
                                        else:
                                            clean_v = v
                                        clean_item[k] = clean_v
                                    csv_data.append(clean_item)
                                
                                # Convert to DataFrame
                                df = pd.DataFrame(csv_data)
                                csv = df.to_csv(index=False)
                                
                                st.download_button(
                                    label="Download CSV Report",
                                    data=csv,
                                    file_name=f"security_report_{selected_subscription_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                    mime="text/csv"
                                )
    else:
        st.markdown("""
        <div class="error-box">
            No subscriptions found. Check application permissions or ensure your tenant has valid Azure subscriptions.
        </div>
        """, unsafe_allow_html=True)
else:
    # Replace HTML welcome box with proper Streamlit markdown
    st.header("Welcome to Generate Security Benchmark Report")
    st.write("This tool helps you analyze and visualize security recommendations for your Azure resources based on Microsoft Security Benchmark.")
    st.write("Please log in using your Azure App Registration credentials in the sidebar to view security recommendations.")
    
    st.subheader("Features:")
    features = [
        "View all Microsoft Security Benchmark recommendations",
        "Filter recommendations by severity and category",
        "Export reports in JSON or CSV format",
        "Track compliance score over time"
    ]
    for feature in features:
        st.markdown(f"- {feature}")
    
    # Add info box styling with custom container
    st.markdown("""
    <style>
    .welcome-container {
        border-left: 4px solid var(--azure-blue);
        background-color: var(--azure-blue-light);
        padding: 10px 15px;
        border-radius: 4px;
    }
    </style>
    """, unsafe_allow_html=True)
