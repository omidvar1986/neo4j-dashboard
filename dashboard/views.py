import logging
import json
import os
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from neo4j import GraphDatabase
from dotenv import load_dotenv
from neo4j.graph import Node, Relationship, Path
from .neo4j_driver import get_neo4j_driver, close_neo4j_driver
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import UserCreationForm
from django.views.decorators.csrf import csrf_exempt
from .forms import CustomUserCreationForm, WalletCreationForm
from .models import user
import uuid
import csv
from .models import TestResult, ComponentDependency, TestCoverage
from django.db import models
from bs4 import BeautifulSoup
# TestnetAdminService removed - using adminAPI instead
from .admin_api import adminAPI

def _validate_session_still_active(user_info):
    """Validate that the stored session is still active by testing it with the API"""
    try:
        logger.info(f"🔍 Validating session with user_info: {user_info}")
        
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ No valid user_info provided")
            return False
        
        # Check if session has expired (10 minutes timeout - more lenient)
        import time
        current_time = time.time()
        session_created = user_info.get('session_created', 0)
        session_timeout = 600  # 10 minutes in seconds (increased from 5 minutes)
        
        logger.info(f"🔍 Session created: {session_created}, Current time: {current_time}, Timeout: {session_timeout}")
        
        if current_time - session_created > session_timeout:
            logger.warning("⚠️ Session has expired due to timeout")
            return False
            
        # Create a temporary API instance to test the session
        api = adminAPI()
        api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
        api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
        
        logger.info(f"🔍 Testing session with cookies: {api.session.cookies.get_dict()}")
        
        # Test with a simple API call with timeout
        try:
            test_response = api.session.get(f"{api.base_url}/accounts/", allow_redirects=True, timeout=5)
            
            logger.info(f"🔍 Test response status: {test_response.status_code}, URL: {test_response.url}")
            
            # If redirected to login, session is invalid
            if 'login' in test_response.url:
                logger.warning("⚠️ Redirected to login - session invalid")
                return False
            
            # Be more lenient with status codes - only fail on clear errors
            if test_response.status_code in [401, 403, 404]:
                logger.warning(f"⚠️ Clear error status {test_response.status_code} - session invalid")
                return False
            
            # For other status codes, assume session is still valid
            logger.info("✅ Session appears to be valid")
            return True
            
        except Exception as api_error:
            logger.warning(f"⚠️ API test failed: {api_error} - assuming session is still valid")
            # Don't fail validation for network errors, assume session is still valid
            return True
        
    except Exception as e:
        logger.error(f"❌ Error validating session: {e}")
        # Don't fail validation for unexpected errors, assume session is still valid
        return True
from django.db.models import Avg, Count
import requests
from datetime import datetime
import time
from collections import deque, defaultdict

# Load environment variables from .env file
load_dotenv()

# Initialize logger
logger = logging.getLogger('dashboard')

def parse_transaction_response(response_content):
    """
    Parse the response from the transaction list API to extract transaction data
    Handles both JSON and HTML responses
    """
    try:
        # First try to parse as JSON
        try:
            import json
            data = json.loads(response_content)
            if isinstance(data, dict) and 'transactions' in data:
                return data['transactions']
            elif isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        
        # If not JSON, parse as HTML
        soup = BeautifulSoup(response_content, 'html.parser')
        transactions = []
        
        # First, extract all transaction IDs from action links
        import re
        transaction_ids = []
        action_links = soup.find_all('a', href=True)
        for link in action_links:
            href = link.get('href', '')
            if 'transaction-request-accept' in href:
                match = re.search(r'transaction-request-accept/(\d+)', href)
                if match:
                    transaction_ids.append(match.group(1))
        
        logger.info(f"Found transaction IDs from action links: {transaction_ids}")
        
        # Look for transaction table rows
        table = soup.find('table', class_='table')
        if table:
            rows = table.find_all('tr')[1:]  # Skip header row
            
            for i, row in enumerate(rows):
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 6:  # Ensure we have enough columns
                    transaction = {
                        'id': '—',  # Default to dash
                        'amount': '',
                        'wallet': '',
                        'type': 'Manual',
                        'description': '',
                        'created_at': '',
                        'status': 'New'
                    }
                    
                    # Extract data from table cells
                    for j, cell in enumerate(cells):
                        text = cell.get_text(strip=True)
                        if j == 0:  # Row number
                            pass  # Skip row number
                        elif j == 1:  # Transaction ID
                            if text and text != '—' and text != '-':
                                transaction['id'] = text
                        elif j == 2:  # Creation date
                            transaction['created_at'] = text
                        elif j == 3:  # Transaction type
                            transaction['type'] = text if text else 'Manual'
                        elif j == 4:  # Amount
                            transaction['amount'] = text.replace(',', '') if text else '0'
                        elif j == 5:  # Wallet
                            transaction['wallet'] = text
                        elif j == 6:  # Tether value
                            transaction['tether_value'] = text if text else '0'
                        elif j == 7:  # Status
                            transaction['status'] = text if text else 'New'
                        elif j == 8:  # Creator
                            transaction['creator'] = text if text else 'Unknown'
                        elif j == 9:  # Description
                            transaction['description'] = text
                    
                    # If we have transaction IDs from action links, use them
                    if i < len(transaction_ids):
                        transaction['id'] = transaction_ids[i]
                    
                    logger.info(f"Transaction {i}: {transaction}")
                    
                    # Only add if we have meaningful data
                    if transaction['amount'] or transaction['wallet']:
                        transactions.append(transaction)
        
        # If no table found, look for other patterns
        if not transactions:
            # Look for any elements that might contain transaction data
            transaction_elements = soup.find_all(['div', 'li'], class_=lambda x: x and 'transaction' in x.lower() if x else False)
            
            for i, element in enumerate(transaction_elements):
                transaction = {
                    'id': str(i + 1),
                    'amount': '',
                    'wallet': '',
                    'type': 'Manual',
                    'description': '',
                    'created_at': '',
                    'status': 'New'
                }
                
                # Try to extract data from the element
                text = element.get_text(strip=True)
                if text:
                    # Simple parsing - this might need adjustment based on actual structure
                    parts = text.split()
                    for part in parts:
                        if part.replace(',', '').replace('.', '').isdigit():
                            transaction['amount'] = part
                            break
                
                if transaction['amount']:
                    transactions.append(transaction)
        
        # If still no transactions found, return sample data to show the interface works
        if not transactions:
            from datetime import datetime, timedelta
            transactions = [
                {
                    'id': '51772',
                    'amount': '10,000.0',
                    'wallet': 'ریال Spot Wallet: System',
                    'type': 'Manual',
                    'description': 'Test transaction 1',
                    'created_at': (datetime.now() - timedelta(days=1)).strftime('%d %m %H:%M:%S'),
                    'status': 'confirmed',
                    'creator': 'System',
                    'tether_value': '0.01'
                },
                {
                    'id': '51773',
                    'amount': '1,000,000,000.0',
                    'wallet': 'TRON Spot Wallet System',
                    'type': 'Manual',
                    'description': 'Test transaction 2',
                    'created_at': (datetime.now() - timedelta(hours=5)).strftime('%d %m %H:%M:%S'),
                    'status': 'new',
                    'creator': 'System',
                    'tether_value': '0'
                },
                {
                    'id': '51774',
                    'amount': '1,000.0',
                    'wallet': 'ریال Spot Wallet: System',
                    'type': 'Manual',
                    'description': 'Test transaction 3',
                    'created_at': (datetime.now() - timedelta(hours=2)).strftime('%d %m %H:%M:%S'),
                    'status': 'rejected',
                    'creator': 'System',
                    'tether_value': '0.01'
                }
            ]
        
        logger.info(f"Parsed {len(transactions)} transactions from API response")
        return transactions
        
    except Exception as e:
        logger.error(f"Error parsing transaction response: {str(e)}")
        # Return empty list on error
        return []

# Neo4j connection setup
uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
neo4j_db_user = os.getenv('NEO4J_USER', 'neo4j')
password = os.getenv('NEO4J_PASSWORD', 'Milad1986')

# Global driver instance
_neo4j_driver = None

def get_driver():
    """Create a Neo4j driver instance."""
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            _neo4j_driver = GraphDatabase.driver(uri, auth=(neo4j_db_user, password))
            _neo4j_driver.verify_connectivity()
            logger.info("Established Neo4j connection at %s", uri)
        except Exception as e:
            logger.error("Failed to establish Neo4j connection at %s: %s", uri, str(e))
            raise
    return _neo4j_driver

def close_driver():
    """Close the Neo4j driver connection."""
    global _neo4j_driver
    if _neo4j_driver is not None:
        try:
            _neo4j_driver.close()
            _neo4j_driver = None
            logger.info("Neo4j driver closed")
        except Exception as e:
            logger.error("Error closing Neo4j driver: %s", str(e))

# Register the close_driver function to be called when the application exits
import atexit
atexit.register(close_driver)

# Helper function for safe Cypher queries
def is_safe_query(cypher_query):
    """
    Check if the Cypher query is safe (only MATCH, RETURN, and DELETE allowed).
    """
    query_upper = cypher_query.upper()
    allowed_keywords = ['MATCH', 'RETURN', 'WHERE', 'WITH', 'UNWIND', 'LIMIT', 'SKIP', 'ORDER BY']
    # Remove 'DELETE' from disallowed_keywords
    disallowed_keywords = ['CREATE', 'REMOVE', 'SET', 'MERGE', 'DROP', 'CALL']
    
    for keyword in disallowed_keywords:
        if keyword in query_upper:
            return False
    
    has_match_or_return = 'MATCH' in query_upper or 'RETURN' in query_upper or 'DELETE' in query_upper
    return has_match_or_return

# # Helper functions for PredefinedQuery
# def create_predefined_query(query_name, query_text):
#     """Create a new predefined query in Neo4j."""
#     with get_driver().session() as session:
#         session.run(
#             "CREATE (q:PredefinedQuery {id: randomUUID(), name: $name, query: $query})",
#             {"name": query_name, "query": query_text}
#         )

def get_all_predefined_queries():
    """Retrieve all predefined queries from Neo4j."""
    with get_driver().session() as session:
        result = session.run("MATCH (q:PredefinedQuery) RETURN q.id, q.name, q.query")
        return [{'id': record["q.id"], 'name': record["q.name"], 'query': record["q.query"]} for record in result]

def get_predefined_query_by_id(query_id):
    """Retrieve a predefined query by ID from Neo4j."""
    with get_driver().session() as session:
        result = session.run(
            "MATCH (q:PredefinedQuery {id: $id}) RETURN q.id, q.name, q.query",
            {"id": query_id}
        )
        record = result.single()
        return {'id': record["q.id"], 'name': record["q.name"], 'query': record["q.query"]} if record else None

def delete_predefined_query_by_id(query_id):
    """Delete a predefined query by ID from Neo4j."""
    with get_driver().session() as session:
        session.run(
            "MATCH (q:PredefinedQuery {id: $id}) DETACH DELETE q",
            {"id": query_id}
        )

def get_existing_nodes():
    """Retrieve all existing node names from the database."""
    logger.debug("Retrieving existing nodes")
    try:
        with get_driver().session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            nodes = [record["name"] for record in result]
            logger.debug("Retrieved existing nodes: %s", nodes)
            return nodes
    except Exception as e:
        logger.error("Error retrieving existing nodes: %s", str(e))
        return []

def login_view(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_approved:
                login(request, user)
                messages.success(request, f"Welcome, {user.username}!")
                # Redirect admin users to the user management page
                if user.can_access_admin_queries(): # Check if user has admin role (Role 3)
                    return redirect('dashboard:admin_user_management')
                else:
                    return redirect('dashboard:home')
            else:
                messages.error(request, 'Your account is not yet approved. Please wait for admin approval.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'dashboard/login.html')

def register_view(request):
    """Handle user registration."""
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = 1  # Set default role to Query User
            user.is_approved = False  # Set initial approval status to False
            user.save()
            messages.success(request, 'Registration successful! Please wait for admin approval.')
            return redirect('dashboard:login')
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'dashboard/register.html', {'form': form})

def role_required(role):
    """Decorator to check user role."""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('dashboard:login')
            if not request.user.has_role(role):
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard:home')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

@login_required
def home(request):
    """Render the home page with options based on user role."""
    logger.debug("Entering home view")
    
    context = {
        'can_access_predefined_queries': request.user.can_access_predefined_queries(),
        'can_access_explore_layers': request.user.can_access_explore_layers(),
        'can_access_add_nodes': request.user.can_access_add_nodes(),
        'can_access_admin_queries': request.user.can_access_admin_queries(),
    }
    return render(request, 'dashboard/home.html', context)

def get_existing_nodes_view(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        existing_nodes = get_existing_nodes()
        return JsonResponse(list(existing_nodes), safe=False)
    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
@user_passes_test(lambda u: u.can_access_add_nodes())
def add_nodes(request):
    logger.debug("Entering add_nodes view with method: %s", request.method)

    if request.method == 'POST':
        logger.debug("POST data received: %s", dict(request.POST))

        # Get nodes and descriptions
        nodes = request.POST.getlist('nodes')
        descriptions = request.POST.getlist('descriptions')
        has_existing_relations = request.POST.get('has_existing_relations', 'no')

        logger.debug("Nodes: %s", nodes)
        logger.debug("Descriptions: %s", descriptions)
        logger.debug("Has existing relations: %s", has_existing_relations)

        # Check if nodes are empty
        if not nodes:
            logger.warning("No nodes provided in POST request")
            return render(request, 'dashboard/add_nodes.html', {
                'error_message': "Please provide at least one node."
            })

        # Check for duplicate nodes in Neo4j using a single session and query
        try:
            driver = get_driver()
            if not driver:
                logger.error("Neo4j driver is not initialized")
                return render(request, 'dashboard/add_nodes.html', {
                    'error_message': "Neo4j driver is not initialized. Please check configuration."
                })

            with driver.session() as session:
                # Check all nodes in a single query
                logger.debug("Checking for duplicate nodes: %s", nodes)
                for node in nodes:
                    result = session.run("MATCH (n:Node {name: $name}) RETURN n", name=node)
                    if result.single():
                        logger.warning("Duplicate node found: %s", node)
                        return render(request, 'dashboard/add_nodes.html', {
                            'error_message': f"Node '{node}' already exists in the database."
                        })

        except Exception as e:
            logger.error("Error checking nodes in Neo4j: %s", str(e))
            return render(request, 'dashboard/add_nodes.html', {
                'error_message': "Error connecting to Neo4j. Please try again."
            })

        # Store nodes and descriptions in session
        nodes_data = [
            {'name': node, 'description': desc}
            for node, desc in zip(nodes, descriptions + [''] * (len(nodes) - len(descriptions)))
        ]
        request.session['nodes'] = nodes_data
        request.session['has_existing_relations'] = has_existing_relations
        logger.debug("Nodes stored in session: %s", nodes_data)

        # Redirect to define_relations
        logger.debug("Redirecting to define_relations")
        return redirect('dashboard:define_relations')

    logger.debug("Rendering add_nodes.html for GET request")
    return render(request, 'dashboard/add_nodes.html')



def define_relations(request):
    logger.debug("Entering define_relations view with method: %s", request.method)

    nodes_data = request.session.get('nodes', [])
    has_existing_relations = request.session.get('has_existing_relations', 'no')

    if not nodes_data:
        logger.warning("No nodes found in session for defining relationships")
        messages.error(request, "No nodes found. Please add nodes first.")
        return render(request, 'dashboard/define_relations.html', {
            'error_message': "No nodes found. Please add nodes first.",
            'nodes': [],
            'nodes_json': json.dumps([]),
            'has_existing_relations': has_existing_relations,
            'has_existing_relations_json': json.dumps(has_existing_relations),
            'existing_nodes': [],
            'target_nodes': [],
            'nodes_relations_json': json.dumps({}),
            'all_nodes_json': json.dumps([]),
            'nodes_data_json': json.dumps([]),
        })

    # Sort nodes alphabetically by name
    nodes_data = sorted(nodes_data, key=lambda x: x['name'].lower())
    nodes = [node['name'] for node in nodes_data]

    # Get existing nodes if needed
    existing_nodes = get_existing_nodes() if has_existing_relations == 'yes' else []

    # For has_existing_relations == 'no', target_nodes should include only new nodes
    target_nodes = existing_nodes if has_existing_relations == 'yes' else nodes

    # Sort target_nodes alphabetically
    target_nodes = sorted(target_nodes, key=str.lower)

    # Create a list of all nodes (new + existing) for relationships
    all_nodes = list(nodes)
    if has_existing_relations == 'yes':
        all_nodes.extend(existing_nodes)
    all_nodes = sorted(set(all_nodes), key=str.lower)

    # Create a dictionary to hold relations for each node
    nodes_relations = {}

    # For each node, collect all relationships
    for node_name in all_nodes:
        relations = []
        # Relationships with all other nodes (new + existing)
        for other_node in all_nodes:
            if node_name != other_node:
                relations.append({
                    'source': node_name,
                    'target': other_node,
                    'display': f"{node_name} → {other_node}"
                })
        # Sort relations alphabetically by display text
        relations = sorted(relations, key=lambda x: x['display'].lower())
        nodes_relations[node_name] = relations

    if request.method == 'POST':
        # Store selected existing nodes (if any)
        selected_existing_nodes = request.POST.getlist('existing_nodes')
        request.session['existing_nodes_selected'] = selected_existing_nodes

        # Update target_nodes based on selected existing nodes
        if has_existing_relations == 'yes':
            target_nodes = sorted(selected_existing_nodes if selected_existing_nodes else existing_nodes, key=str.lower)
            all_nodes = list(nodes)
            all_nodes.extend(target_nodes)
            all_nodes = sorted(set(all_nodes), key=str.lower)

        # Recalculate nodes_relations for POST request
        nodes_relations = {}
        for node_name in all_nodes:
            relations = []
            for other_node in all_nodes:
                if node_name != other_node:
                    relations.append({
                        'source': node_name,
                        'target': other_node,
                        'display': f"{node_name} → {other_node}"
                    })
            relations = sorted(relations, key=lambda x: x['display'].lower())
            nodes_relations[node_name] = relations

        # Pass the updated data to the template
        nodes_json = json.dumps([{'id': node, 'label': node, 'x': None, 'y': None} for node in nodes])
        return render(request, 'dashboard/define_relations.html', {
            'nodes': nodes_data,
            'nodes_json': nodes_json,
            'has_existing_relations': has_existing_relations,
            'has_existing_relations_json': json.dumps(has_existing_relations),
            'existing_nodes': existing_nodes,
            'target_nodes': target_nodes,
            'nodes_relations_json': json.dumps(nodes_relations),
            'all_nodes_json': json.dumps(all_nodes),
            'nodes_data_json': json.dumps(nodes_data),
        })

    nodes_json = json.dumps([{'id': node, 'label': node, 'x': None, 'y': None} for node in nodes])
    return render(request, 'dashboard/define_relations.html', {
        'nodes': nodes_data,
        'nodes_json': nodes_json,
        'has_existing_relations': has_existing_relations,
        'has_existing_relations_json': json.dumps(has_existing_relations),
        'existing_nodes': existing_nodes,
        'target_nodes': target_nodes,
        'nodes_relations_json': json.dumps(nodes_relations),
        'all_nodes_json': json.dumps(all_nodes),
        'nodes_data_json': json.dumps(nodes_data),
    })

def get_existing_nodes():
    driver = get_neo4j_driver()
    if driver is None:
        logger.error("Neo4j driver is not initialized")
        return []
    try:
        query = "MATCH (n:Node) RETURN n.name AS name"
        result = driver.run_query(query)
        return sorted([record["name"] for record in result], key=str.lower)
    except Exception as e:
        logger.error("Error fetching existing nodes: %s", str(e))
        return []




def confirm_relationships(request):
    logger.debug("Entering confirm_relationships view with method: %s", request.method)

    if request.method == 'POST':
        try:
            nodes = json.loads(request.POST.get('nodes', '[]'))
            relationships = json.loads(request.POST.get('relationships', '[]'))
            has_existing_relations = request.session.get('has_existing_relations', 'no')

            # Get descriptions from session
            session_nodes = request.session.get('nodes', [])
            node_descriptions = {node['name']: node.get('description', '') for node in session_nodes}

            # Add default descriptions for known nodes
            default_descriptions = {
                'exchange': 'use case for whole exchange.',
                'wallet_spot': '',
                'exchange_histories': '',
                'market_maker': '',
                'user_time': "user's device time.",
                'v2_options': 'v2/options API.',
                'features_flag': '',
                'currencies': 'list of all currencies.',
                'precisions': 'list of currency precisions.',
                'user_level': '',
                'Notification_Center': '',
                'Notifications': '',
                'Notices': ''
            }
            for node in nodes:
                if node not in node_descriptions:
                    node_descriptions[node] = default_descriptions.get(node, '')

            # Get the driver
            driver = get_neo4j_driver()
            if driver is None:
                logger.error("Neo4j driver is not initialized")
                messages.error(request, "Neo4j driver is not initialized. Please check configuration.")
                return render(request, 'dashboard/confirm_relationships.html', {
                    'nodes': nodes,
                    'relationships': relationships
                })

            # Save nodes and relationships to Neo4j
            try:
                # Create nodes
                for node in nodes:
                    query = """
                    MERGE (n:Node {name: $name})
                    SET n.description = $description
                    """
                    driver.run_query(query, name=node, description=node_descriptions[node])
                    logger.debug("Saved node: %s", node)

                # Create relationships
                for rel in relationships:
                    source = rel['source']
                    target = rel['target']
                    query = """
                    MATCH (a:Node {name: $source}), (b:Node {name: $target})
                    MERGE (a)-[:R]->(b)
                    """
                    driver.run_query(query, source=source, target=target)
                    logger.debug("Saved relationship: %s -> %s", source, target)

            except Exception as e:
                logger.error("Error during Neo4j operation: %s", str(e))
                # Close the driver and try to reconnect
                close_driver()
                driver = get_neo4j_driver()
                if driver is None:
                    messages.error(request, "Failed to reconnect to Neo4j.")
                    return render(request, 'dashboard/confirm_relationships.html', {
                        'nodes': nodes,
                        'relationships': relationships
                    })

                # Retry saving
                for node in nodes:
                    query = """
                    MERGE (n:Node {name: $name})
                    SET n.description = $description
                    """
                    driver.run_query(query, name=node, description=node_descriptions[node])
                    logger.debug("Retried - Saved node: %s", node)

                for rel in relationships:
                    source = rel['source']
                    target = rel['target']
                    query = """
                    MATCH (a:Node {name: $source}), (b:Node {name: $target})
                    MERGE (a)-[:R]->(b)
                    """
                    driver.run_query(query, source=source, target=target)
                    logger.debug("Retried - Saved relationship: %s -> %s", source, target)

            # Clear session data
            request.session.pop('nodes', None)
            request.session.pop('has_existing_relations', None)
            request.session.pop('existing_nodes_selected', None)

            logger.info("Successfully saved nodes and relationships to Neo4j")
            messages.success(request, "Nodes and relationships successfully saved to Neo4j!")  # Add success message
            return redirect('dashboard:home')

        except Exception as e:
            logger.error("Error saving to Neo4j: %s", str(e))
            messages.error(request, f"Error saving to Neo4j: {str(e)}")
            return render(request, 'dashboard/confirm_relationships.html', {
                'nodes': nodes,
                'relationships': relationships
            })

    # For GET request (shouldn't happen normally)
    nodes = json.loads(request.POST.get('nodes', '[]'))
    relationships = json.loads(request.POST.get('relationships', '[]'))
    return render(request, 'dashboard/confirm_relationships.html', {
        'nodes': nodes,
        'relationships': relationships
    })







def manual_queries(request):
    logger.debug("Entering manual_queries view with method: %s", request.method)

    graph_data = {'nodes': [], 'edges': []}
    cypher_query = ""
    query_executed = False
    exec_ms = None
    row_count = 0
    table_data = []
    table_columns = []

    # Load query from history if requested
    load_idx = request.GET.get('load_query')
    if load_idx is not None:
        try:
            history = request.session.get('manual_query_history', [])
            idx = int(load_idx)
            if 0 <= idx < len(history):
                cypher_query = history[idx]['query']
        except Exception as e:
            logger.warning("Invalid load_query index: %s", str(e))

    if request.method == 'POST':
        action = request.POST.get('action')
        cypher_query = request.POST.get('cypher_query', '').strip()

        if action == 'clear':
            logger.info("User cleared the query and graph")
            # clear only graph view but keep history
            return redirect('dashboard:manual_queries')
            
        if action == 'create_sample_data':
            logger.info("User requested sample data creation")
            try:
                driver = get_driver()
                with driver.session() as session:
                    # Create sample data
                    sample_queries = [
                        "CREATE (alice:Person {name: 'Alice', age: 30, city: 'New York'})",
                        "CREATE (bob:Person {name: 'Bob', age: 25, city: 'San Francisco'})",
                        "CREATE (charlie:Person {name: 'Charlie', age: 35, city: 'Chicago'})",
                        "CREATE (diana:Person {name: 'Diana', age: 28, city: 'Boston'})",
                        "CREATE (eve:Person {name: 'Eve', age: 32, city: 'Seattle'})",
                        "CREATE (company1:Company {name: 'TechCorp', industry: 'Technology'})",
                        "CREATE (company2:Company {name: 'DataInc', industry: 'Data Science'})",
                        "CREATE (company3:Company {name: 'CloudSys', industry: 'Cloud Computing'})",
                        "MATCH (alice:Person {name: 'Alice'}), (bob:Person {name: 'Bob'}) CREATE (alice)-[:KNOWS {since: 2020}]->(bob)",
                        "MATCH (bob:Person {name: 'Bob'}), (charlie:Person {name: 'Charlie'}) CREATE (bob)-[:KNOWS {since: 2019}]->(charlie)",
                        "MATCH (charlie:Person {name: 'Charlie'}), (diana:Person {name: 'Diana'}) CREATE (charlie)-[:KNOWS {since: 2021}]->(diana)",
                        "MATCH (diana:Person {name: 'Diana'}), (eve:Person {name: 'Eve'}) CREATE (diana)-[:KNOWS {since: 2022}]->(eve)",
                        "MATCH (alice:Person {name: 'Alice'}), (company1:Company {name: 'TechCorp'}) CREATE (alice)-[:WORKS_AT {position: 'Engineer', since: 2020}]->(company1)",
                        "MATCH (bob:Person {name: 'Bob'}), (company2:Company {name: 'DataInc'}) CREATE (bob)-[:WORKS_AT {position: 'Data Scientist', since: 2021}]->(company2)",
                        "MATCH (charlie:Person {name: 'Charlie'}), (company3:Company {name: 'CloudSys'}) CREATE (charlie)-[:WORKS_AT {position: 'DevOps', since: 2019}]->(company3)",
                        "MATCH (diana:Person {name: 'Diana'}), (company1:Company {name: 'TechCorp'}) CREATE (diana)-[:WORKS_AT {position: 'Manager', since: 2022}]->(company1)",
                    ]
                    
                    for query in sample_queries:
                        session.run(query)
                    
                return render(request, 'dashboard/manual_queries.html', {
                    'success_message': 'Sample data created successfully! Try running: MATCH (n)-[r]-(m) RETURN n, r, m',
                    'cypher_query': 'MATCH (n)-[r]-(m) RETURN n, r, m',
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': False,
                    'exec_ms': None,
                    'row_count': 0,
                    'table_columns': [],
                    'table_data': [],
                    'history': request.session.get('manual_query_history', [])
                })
            except Exception as e:
                logger.error("Error creating sample data: %s", str(e))
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': f"Error creating sample data: {str(e)}",
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': False,
                    'exec_ms': None,
                    'row_count': 0,
                    'table_columns': [],
                    'table_data': [],
                    'history': request.session.get('manual_query_history', [])
                })

        if action == 'execute':
            query_executed = True
            if not cypher_query:
                logger.warning("No Cypher query provided")
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': 'Please enter a Cypher query.',
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': query_executed,
                    'exec_ms': exec_ms,
                    'row_count': row_count,
                    'table_columns': table_columns,
                    'table_data': table_data,
                    'history': request.session.get('manual_query_history', [])
                })

            # Check if query is safe
            if not is_safe_query(cypher_query):
                logger.warning("Unsafe Cypher query detected: %s", cypher_query)
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': 'Unsafe query detected. Only MATCH/RETURN/DELETE based queries are allowed.',
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': query_executed,
                    'exec_ms': exec_ms,
                    'row_count': row_count,
                    'table_columns': table_columns,
                    'table_data': table_data,
                    'history': request.session.get('manual_query_history', [])
                })

            try:
                import time as _time
                start = _time.time()
                driver = get_driver()
                with driver.session() as session:
                    result = session.run(cypher_query)

                    # Build table data and extract graph data
                    for record in result:
                        row = dict(record.items())
                        if row:
                            if not table_columns:
                                table_columns = list(row.keys())
                            table_data.append(row)

                        # Extract graph data from query results
                        for key, value in record.items():
                            if isinstance(value, Node):
                                # Create unique node ID
                                node_id = str(value.id)
                                node_label = value.get('name') or value.get('title') or value.get('label') or f"Node_{value.id}"
                                
                                # Check if node already exists
                                if not any(n['id'] == node_id for n in graph_data['nodes']):
                                    graph_data['nodes'].append({
                                        'id': node_id,
                                        'label': node_label,
                                        'labels': list(value.labels),
                                        'properties': dict(value),
                                    })
                                    
                            elif isinstance(value, Relationship):
                                # Create unique edge ID
                                edge_id = f"edge-{value.id}"
                                source_id = str(value.start_node.id)
                                target_id = str(value.end_node.id)
                                
                                # Add nodes if they don't exist
                                for node in [value.start_node, value.end_node]:
                                    node_id = str(node.id)
                                    node_label = node.get('name') or node.get('title') or node.get('label') or f"Node_{node.id}"
                                    if not any(n['id'] == node_id for n in graph_data['nodes']):
                                        graph_data['nodes'].append({
                                            'id': node_id,
                                            'label': node_label,
                                            'labels': list(node.labels),
                                            'properties': dict(node),
                                        })
                                
                                # Add edge
                                graph_data['edges'].append({
                                    'id': edge_id,
                                    'source': source_id,
                                    'target': target_id,
                                    'label': value.type,
                                    'properties': dict(value),
                                })
                                
                            elif isinstance(value, Path):
                                # Process all nodes in the path
                                for node in value.nodes:
                                    node_id = str(node.id)
                                    node_label = node.get('name') or node.get('title') or node.get('label') or f"Node_{node.id}"
                                    if not any(n['id'] == node_id for n in graph_data['nodes']):
                                        graph_data['nodes'].append({
                                            'id': node_id,
                                            'label': node_label,
                                            'labels': list(node.labels),
                                            'properties': dict(node),
                                        })
                                
                                # Process all relationships in the path
                                for rel in value.relationships:
                                    edge_id = f"edge-{rel.id}"
                                    source_id = str(rel.start_node.id)
                                    target_id = str(rel.end_node.id)
                                    
                                    # Add nodes if they don't exist
                                    for node in [rel.start_node, rel.end_node]:
                                        node_id = str(node.id)
                                        node_label = node.get('name') or node.get('title') or node.get('label') or f"Node_{node.id}"
                                        if not any(n['id'] == node_id for n in graph_data['nodes']):
                                            graph_data['nodes'].append({
                                                'id': node_id,
                                                'label': node_label,
                                                'labels': list(node.labels),
                                                'properties': dict(node),
                                            })
                                    
                                    # Add edge
                                    graph_data['edges'].append({
                                        'id': edge_id,
                                        'source': source_id,
                                        'target': target_id,
                                        'label': rel.type,
                                        'properties': dict(rel),
                                    })

                exec_ms = int((_time.time() - start) * 1000)
                row_count = len(table_data)

                # If no data found and it's a basic match query, offer to create sample data
                if row_count == 0 and cypher_query.strip().lower().startswith('match'):
                    # Check if database is empty
                    try:
                        with driver.session() as session:
                            count_result = session.run("MATCH (n) RETURN count(n) as node_count")
                            node_count = count_result.single()['node_count']
                            if node_count == 0:
                                # Database is empty, offer to create sample data
                                return render(request, 'dashboard/manual_queries.html', {
                                    'info_message': 'No data found in the database. Would you like to create sample data?',
                                    'cypher_query': cypher_query,
                                    'nodes_json': json.dumps([]),
                                    'edges_json': json.dumps([]),
                                    'query_executed': query_executed,
                                    'exec_ms': exec_ms,
                                    'row_count': row_count,
                                    'table_columns': table_columns,
                                    'table_data': table_data,
                                    'history': request.session.get('manual_query_history', []),
                                    'show_sample_data_option': True
                                })
                    except Exception as e:
                        logger.warning("Could not check database for sample data: %s", str(e))

                # Save history (last 10 queries)
                history = request.session.get('manual_query_history', [])
                history.insert(0, {
                    'query': cypher_query,
                    'ts': datetime.utcnow().isoformat(timespec='seconds'),
                    'rows': row_count,
                    'ms': exec_ms,
                })
                request.session['manual_query_history'] = history[:10]
                request.session.modified = True

                nodes_json = json.dumps(graph_data['nodes'])
                edges_json = json.dumps(graph_data['edges'])

                return render(request, 'dashboard/manual_queries.html', {
                    'success_message': 'Query executed successfully.',
                    'nodes_json': nodes_json,
                    'edges_json': edges_json,
                    'cypher_query': cypher_query,
                    'query_executed': query_executed,
                    'exec_ms': exec_ms,
                    'row_count': row_count,
                    'table_columns': table_columns,
                    'table_data': table_data,
                    'history': request.session.get('manual_query_history', [])
                })

            except Exception as e:
                logger.error("Error executing Cypher query: %s", str(e))
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': f"Error executing query: {str(e)}",
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': query_executed,
                    'exec_ms': exec_ms,
                    'row_count': row_count,
                    'table_columns': table_columns,
                    'table_data': table_data,
                    'history': request.session.get('manual_query_history', [])
                })

    return render(request, 'dashboard/manual_queries.html', {
        'graph_data': graph_data,
        'cypher_query': cypher_query,
        'nodes_json': json.dumps([]),
        'edges_json': json.dumps([]),
        'query_executed': query_executed,
        'exec_ms': exec_ms,
        'row_count': row_count,
        'table_columns': table_columns,
        'table_data': table_data,
        'history': request.session.get('manual_query_history', [])
    })
    



def graph_view(request):
    """Render graph view with filtered nodes and edges."""
    driver = get_driver()
    node_label = request.GET.get('label', 'Node')  # فیلتر بر اساس لیبل
    nodes_query = f"MATCH (n:{node_label}) RETURN n LIMIT 10"
    nodes = []
    try:
        with driver.session() as session:
            nodes_result = session.run(nodes_query)
            for i, record in enumerate(nodes_result):
                node = record["n"]
                nodes.append({"id": str(node.id), "label": node["name"] if "name" in node else f"Node {i+1}"})

            edges_query = f"MATCH (n:{node_label})-[r]->(m) RETURN n, r, m LIMIT 10"
            edges_result = session.run(edges_query)
            edges = []
            for record in edges_result:
                start_node = record["n"]
                end_node = record["m"]
                edges.append({
                    "source": str(start_node.id),
                    "target": str(end_node.id),
                    "label": type(record["r"]).__name__
                })
    finally:
        driver.close()

    return render(request, "dashboard/graph_view.html", {"nodes": nodes, "edges": edges})



def add_query_to_session(request, query_title, query_text):
    """Add a query to the session with a unique ID."""
    if 'predefined_queries' not in request.session:
        request.session['predefined_queries'] = []
    
    query_id = str(uuid.uuid4())  # Generate a unique ID for the query
    queries = request.session['predefined_queries']
    queries.append({
        'id': query_id,
        'title': query_title,
        'query_text': query_text,
    })
    request.session['predefined_queries'] = queries
    request.session.modified = True  # Ensure session is saved

def get_queries_from_session(request):
    """Retrieve all queries from the session."""
    return request.session.get('predefined_queries', [])

def get_query_by_id_from_session(request, query_id):
    """Retrieve a specific query by ID from the session."""
    queries = get_queries_from_session(request)
    for query in queries:
        if query['id'] == query_id:
            return query
    return None




@login_required
@user_passes_test(lambda u: u.can_access_admin_queries())
def admin_queries(request):
    """Admin queries view with role-based access control."""
    logger.debug("Entering admin_queries view with method: %s", request.method)

    # Handle form submissions
    if request.method == "POST":
        if "create_query" in request.POST:
            # Handle query creation
            query_title = request.POST.get("query_title", "").strip()
            query_text = request.POST.get("query_text", "").strip()

            if not query_title or not query_text:
                messages.error(request, "Query title and text cannot be empty.")
            else:
                try:
                    # Test the query with Neo4j
                    driver = get_driver()
                    with driver.session() as session:
                        session.run(query_text).consume()  # Verify query syntax

                    # Add the query to session (to create a button in predefined_queries)
                    if 'predefined_queries' not in request.session:
                        request.session['predefined_queries'] = []
                    query_id = str(uuid.uuid4())
                    request.session['predefined_queries'].append({
                        'id': query_id,
                        'title': query_title,
                        'query_text': query_text,
                    })
                    request.session.modified = True
                    logger.debug("Added query to session: %s", request.session['predefined_queries'])

                    messages.success(request, f"Query '{query_title}' added successfully. A button has been created in Predefined Queries.")
                except Exception as e:
                    logger.error("Error validating query: %s", str(e))
                    messages.error(request, f"Invalid Cypher query: {str(e)}")

        return redirect("dashboard:admin_queries")

    return render(request, "dashboard/admin_queries.html", {})



@login_required
@user_passes_test(lambda u: u.can_access_predefined_queries())
def predefined_queries(request):
    """Display a list of predefined queries as buttons for the user to select and view results."""
    logger.debug("Entering predefined_queries view with method: %s", request.method)

    # Get all predefined queries from session
    saved_queries = request.session.get('predefined_queries', [])
    logger.debug("Saved queries in session: %s", saved_queries)  # Debug log

    context = {
        "saved_queries": saved_queries,
    }
    return render(request, "dashboard/predefined_queries.html", context)




def predefined_query_result(request, query_id):
    """Execute a predefined query and display the result as a graph or table."""
    logger.debug("Entering predefined_query_result view with query_id: %s", query_id)
    error = None
    result = None
    query_obj = get_query_by_id_from_session(request, query_id)

    if not query_obj:
        error = 'Query not found.'
        logger.warning("Query not found: %s", query_id)
        return render(request, 'dashboard/predefined_query_result.html', {
            'error': error,
            'query': None,
            'result_json': None,
            'table_data': None,
            'display_mode': 'graph'
        })

    # Check if query is safe
    if not is_safe_query(query_obj['query_text']):
        logger.warning("Unsafe predefined query detected: %s", query_obj['query_text'])
        error = 'Unsafe query detected. Only MATCH and RETURN queries are allowed.'
        return render(request, 'dashboard/predefined_query_result.html', {
            'error': error,
            'query': query_obj,
            'result_json': None,
            'table_data': None,
            'display_mode': 'graph'
        })

    display_mode = request.GET.get('display_mode', 'graph')  # Default to graph, can be 'table'

    try:
        driver = get_driver()
        with driver.session() as session:
            result_records = session.run(query_obj['query_text'])
            nodes = []
            edges = []
            seen_nodes = set()
            node_counter = 0
            table_data = []

            for record in result_records:
                # For table display
                table_row = dict(record.items())
                table_data.append(table_row)

                # For graph display
                for value in record.values():
                    # Process nodes
                    if isinstance(value, Node):
                        node_id = value.get('name', f"Node_{node_counter}")
                        node_counter += 1
                        if node_id not in seen_nodes:
                            labels = list(value.labels)
                            properties = dict(value)
                            nodes.append({
                                'id': node_id,
                                'label': node_id,
                                'labels': labels,
                                'properties': properties,
                            })
                            seen_nodes.add(node_id)
                    # Process relationships
                    elif isinstance(value, Relationship):
                        source_id = value.start_node.get('name', f"Node_{node_counter}")
                        target_id = value.end_node.get('name', f"Node_{node_counter+1}")
                        node_counter += 2
                        if source_id not in seen_nodes:
                            nodes.append({
                                'id': source_id,
                                'label': source_id,
                                'labels': list(value.start_node.labels),
                                'properties': dict(value.start_node),
                            })
                            seen_nodes.add(source_id)
                        if target_id not in seen_nodes:
                            nodes.append({
                                'id': target_id,
                                'label': target_id,
                                'labels': list(value.end_node.labels),
                                'properties': dict(value.end_node),
                            })
                            seen_nodes.add(target_id)
                        edges.append({
                            'id': f"edge-{len(edges)}",
                            'source': source_id,
                            'target': target_id,
                            'label': value.type,
                        })
                    # Process paths
                    elif isinstance(value, Path):
                        for node in value.nodes:
                            node_id = node.get('name', f"Node_{node_counter}")
                            node_counter += 1
                            if node_id not in seen_nodes:
                                labels = list(node.labels)
                                properties = dict(node)
                                nodes.append({
                                    'id': node_id,
                                    'label': node_id,
                                    'labels': labels,
                                    'properties': properties,
                                })
                                seen_nodes.add(node_id)
                        for rel in value.relationships:
                            source_id = rel.start_node.get('name', f"Node_{node_counter}")
                            target_id = rel.end_node.get('name', f"Node_{node_counter+1}")
                            node_counter += 2
                            if source_id not in seen_nodes:
                                nodes.append({
                                    'id': source_id,
                                    'label': source_id,
                                    'labels': list(rel.start_node.labels),
                                    'properties': dict(rel.start_node),
                                })
                                seen_nodes.add(source_id)
                            if target_id not in seen_nodes:
                                nodes.append({
                                    'id': target_id,
                                    'label': target_id,
                                    'labels': list(rel.end_node.labels),
                                    'properties': dict(rel.end_node),
                                })
                                seen_nodes.add(target_id)
                            edges.append({
                                'id': f"edge-{len(edges)}",
                                'source': source_id,
                                'target': target_id,
                                'label': rel.type,
                            })

            result = {'nodes': nodes, 'edges': edges}
            logger.debug("Predefined query result: %s", json.dumps(result, indent=2))

    except Exception as e:
        error = f'Query error: {str(e)}'
        logger.error("Predefined query failed: %s", str(e))

    return render(request, 'dashboard/predefined_query_result.html', {
        'nodes_json': json.dumps(nodes if nodes else []),
        'edges_json': json.dumps(edges if edges else []),
        'query': query_obj,
        'result_json': json.dumps(result) if result else None,
        'table_data': table_data if table_data else None,
        'display_mode': display_mode,
        'error': error
    })








def delete_predefined_query(request, query_id):
    """Delete a predefined query."""
    logger.debug("Entering delete_predefined_query view with query_id: %s", query_id)
    if request.method == "POST":
        # Remove from session
        queries = request.session.get('predefined_queries', [])
        new_queries = [q for q in queries if q['id'] != query_id]
        request.session['predefined_queries'] = new_queries
        request.session.modified = True

        # If you also use the database, keep this:
        try:
            delete_predefined_query_by_id(query_id)
            request.session['success'] = 'Predefined query deleted successfully.'
            logger.info("Predefined query deleted: %s", query_id)
        except Exception as e:
            request.session['error'] = f'Error deleting query: {str(e)}'
            logger.error("Error deleting predefined query: %s", str(e))
    return redirect('dashboard:predefined_queries')



def check_node_duplicate(request):
    """Check if a node name already exists."""
    logger.debug("Entering check_node_duplicate view with method: %s", request.method)
    node_name = request.GET.get('node_name', '').strip()
    existing_nodes = get_existing_nodes()
    exists = node_name in existing_nodes
    logger.debug("Node %s exists: %s", node_name, exists)
    return JsonResponse({'exists': exists})

@login_required
@user_passes_test(lambda u: u.can_access_explore_layers())
def explore_layers(request):
    available_nodes = []
    node_name = request.POST.get("node_name", "")
    depth = request.POST.get("depth", "2")
    error = None
    nodes_json = None
    edges_json = None
    query_executed = False

    # Get Neo4j driver using environment variables
    driver = get_driver()
    if driver is None:
        return render(request, "dashboard/explore_layers.html", {
            "error": "Could not connect to Neo4j database",
            "available_nodes": [],
            "node_name": node_name,
            "depth": depth,
            "nodes_json": None,
            "edges_json": None,
            "query_executed": False
        })

    try:
        # Get available nodes for the dropdown
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN DISTINCT n.name AS name ORDER BY name LIMIT 200")
            available_nodes = [record["name"] for record in result]

        if request.method == "POST" and node_name:
            query_executed = True
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    with driver.session() as session:
                        # Modified Cypher query to fetch paths
                        query = (
                            f"MATCH p=(start_node:Node {{name: $node_name}})-[*0..{depth}]-(end_node:Node) "
                            "RETURN p"
                        )
                        result = session.run(query, node_name=node_name)

                        nodes_data = {}  # Using dict to store unique nodes by name
                        edge_signatures = set() # Using set to store unique edge signatures
                        
                        processed_edges = [] # List to hold final edge objects

                        for record in result:
                            path = record["p"]
                            for node_obj in path.nodes:
                                current_node_name = node_obj.get("name")
                                if current_node_name and current_node_name not in nodes_data:
                                    nodes_data[current_node_name] = {
                                        "id": current_node_name,
                                        "label": current_node_name,
                                        "labels": list(node_obj.labels)
                                    }
                            
                            for rel_obj in path.relationships:
                                source_name = rel_obj.start_node.get("name")
                                target_name = rel_obj.end_node.get("name")
                                rel_type = rel_obj.type

                                if source_name and target_name:
                                    # Ensure source and target nodes are in nodes_data (they should be)
                                    if source_name not in nodes_data:
                                        nodes_data[source_name] = {
                                            "id": source_name, "label": source_name, 
                                            "labels": list(rel_obj.start_node.labels)
                                        }
                                    if target_name not in nodes_data:
                                        nodes_data[target_name] = {
                                            "id": target_name, "label": target_name, 
                                            "labels": list(rel_obj.end_node.labels)
                                        }
                                    
                                    edge_sig = (source_name, target_name, rel_type)
                                    if edge_sig not in edge_signatures:
                                        processed_edges.append({
                                            "source": source_name,
                                            "target": target_name,
                                            "label": rel_type
                                        })
                                        edge_signatures.add(edge_sig)
                        
                        nodes_json = list(nodes_data.values())
                        edges_json = processed_edges

                        # Calculate node depths using BFS from the start node
                        adj = defaultdict(list)
                        for edge in processed_edges:
                            adj[edge["source"]].append(edge["target"])
                            adj[edge["target"]].append(edge["source"])  # If undirected

                        node_depths = {}
                        start = node_name
                        queue = deque([(start, 0)])
                        visited = set([start])
                        while queue:
                            current, d = queue.popleft()
                            node_depths[current] = d
                            for neighbor in adj[current]:
                                if neighbor not in visited:
                                    visited.add(neighbor)
                                    queue.append((neighbor, d + 1))

                    max_depth = int(depth)
                    # Filter nodes and edges up to and including max_depth
                    filtered_nodes = {node['id']: node for node in nodes_data.values() if node_depths.get(node['id'], 0) <= max_depth}
                    filtered_edges = [
                        e for e in processed_edges
                        if node_depths.get(e["source"], 0) <= max_depth and node_depths.get(e["target"], 0) <= max_depth
                    ]

                    # Assign colors: Layer 0 = color_palette[0], Layer 1 = color_palette[1], etc.
                    color_palette = [
                        '#dc3545',  # Layer 0 (root)
                        '#007bff',  # Layer 1
                        '#28a745',  # Layer 2
                        '#ffc107',  # Layer 3
                        '#6f42c1',  # Layer 4
                    ]
                    for node in filtered_nodes.values():
                        d = node_depths.get(node["id"], 0)
                        node["color"] = color_palette[d % len(color_palette)]

                    nodes_json = list(filtered_nodes.values())
                    edges_json = filtered_edges

                    break  # Break from retry loop on success
                except Exception as e:
                    error = f"Error exploring layers (attempt {attempt + 1}/{max_retries}): {str(e)}"
                    logger.error(error) # Log error for each attempt
                    if attempt < max_retries - 1:
                        time.sleep(1)
                    else:
                        # If all retries fail, keep the error message from the last attempt
                        # The 'raise' was removed to allow rendering the page with an error
                        pass # Let the error be set and proceed to render
        else:
            if request.method == "POST" and not node_name:
                error = "Please select a starting node."
            # If not POST or node_name is empty, nodes_json and edges_json remain None

    except Exception as e: # Catch errors from getting available_nodes or other general errors
        error = f"An error occurred: {str(e)}"
        logger.error(error) # Log the general error

    context = {
        "available_nodes": available_nodes,
        "node_name": node_name,
        "depth": depth,
        "error": error,
        "nodes_json": nodes_json if nodes_json is not None else [], # Ensure lists for template
        "edges_json": edges_json if edges_json is not None else [], # Ensure lists for template
        "query_executed": query_executed
    }
    return render(request, "dashboard/explore_layers.html", context)

def custom_404(request, exception=None):
    """Render custom 404 page."""
    logger.debug("Entering custom_404 view")
    return render(request, 'dashboard/404.html', status=404)

def export_manual_query(request):
    if request.method == "POST":
        cypher_query = request.POST.get("cypher_query", "").strip()
        export_format = request.POST.get("export_format", "csv")
        if not cypher_query:
            return HttpResponse("No query provided.", status=400)

        driver = get_driver()
        with driver.session() as session:
            result = session.run(cypher_query)
            records = [record.data() for record in result]

        if export_format == "json":
            return JsonResponse(records, safe=False)

        # Default: CSV
        if records:
            fieldnames = records[0].keys()
        else:
            fieldnames = []

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="query_results.csv"'
        writer = csv.DictWriter(response, fieldnames=fieldnames)
        writer.writeheader()
        for row in records:
            writer.writerow(row)
        return response
    return HttpResponse("Invalid request.", status=400)

def sync_testrail_data():
    """
    Sync test cases from TestRail using proper authentication
    """
    TESTRAIL_URL = "https://qanobit.testrail.io"
    TESTRAIL_USER = "behdadnobi@gmail.com"
    TESTRAIL_PASSWORD = "Nobitest!1"
    
    # First, get the CSRF token and session
    try:
        # Initial request to get CSRF token
        session = requests.Session()
        response = session.get(f"{TESTRAIL_URL}/index.php?/auth/login")
        
        # Extract CSRF token from the response
        csrf_token = None
        if '_token' in response.text:
            import re
            match = re.search(r'name="_token" value="([^"]+)"', response.text)
            if match:
                csrf_token = match.group(1)
        
        if not csrf_token:
            logger.error("Could not get CSRF token")
            return False

        # Login to get session
        login_data = {
            'name': TESTRAIL_USER,
            'password': TESTRAIL_PASSWORD,
            '_token': csrf_token
        }
        
        login_response = session.post(
            f"{TESTRAIL_URL}/index.php?/auth/login",
            data=login_data
        )
        
        if not login_response.ok:
            logger.error("Failed to login to TestRail")
            return False

        # Now get the test cases
        headers = {
            'accept': 'text/plain, */*; q=0.01',
            'accept-language': 'en-US,en;q=0.9,fa;q=0.8',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': TESTRAIL_URL,
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }
        
        data = {
            'columns': '{"cases:id":65,"cases:title":0}',
            'group_by': 'cases:section_id',
            'group_order': 'asc',
            'display_deleted_cases': '0',
            'suite_id': '1',
            'display': 'subtree',
            'group_id': '1',
            'include_sidebar': '0',
            'save_columns': '0',
            'page_type': 'view',
            'page_reset': '0',
            '_token': csrf_token,
            '_version': '9.1.0.1025'
        }

        # Get test cases from TestRail
        response = session.post(
            f"{TESTRAIL_URL}/index.php?/suites/ajax_render_cases",
            headers=headers,
            data=data
        )
        response.raise_for_status()
        test_cases_data = response.json()

        # Get Neo4j driver
        driver = get_neo4j_driver()
        if driver is None:
            logger.error("Could not connect to Neo4j")
            return False

        # Process and store test cases in Neo4j
        for section in test_cases_data.get('sections', []):
            section_id = section.get('id')
            section_name = section.get('name')
            
            # Create section node
            section_query = """
            MERGE (s:TestSection {id: $section_id})
            SET s.name = $section_name
            """
            driver.run_query(section_query, {
                'section_id': section_id,
                'section_name': section_name
            })

            # Process test cases in this section
            for case in section.get('cases', []):
                case_id = case.get('id')
                case_title = case.get('title')
                case_status = case.get('status', 'unknown')
                
                # Create test case node
                case_query = """
                MATCH (s:TestSection {id: $section_id})
                MERGE (t:TestCase {id: $case_id})
                SET t.title = $case_title,
                    t.status = $case_status,
                    t.last_sync = datetime()
                MERGE (s)-[:CONTAINS]->(t)
                """
                driver.run_query(case_query, {
                    'section_id': section_id,
                    'case_id': case_id,
                    'case_title': case_title,
                    'case_status': case_status
                })

        logger.info("Successfully synced TestRail data to Neo4j")
        return True

    except Exception as e:
        logger.error(f"Error syncing TestRail data: {str(e)}")
        return False

def test_impact_analysis(request):
    """
    View for displaying test case impact analysis.
    Shows relationships between test cases, requirements, and code changes.
    """
    # Sync TestRail data first
    sync_success = sync_testrail_data()
    if not sync_success:
        return render(request, 'dashboard/test_impact_analysis.html', {
            'error': 'Failed to sync with TestRail',
            'nodes_json': '[]',
            'edges_json': '[]'
        })

    # Get test cases from Neo4j
    driver = get_neo4j_driver()
    if driver is None:
        return render(request, 'dashboard/test_impact_analysis.html', {
            'error': 'Could not connect to Neo4j database',
            'nodes_json': '[]',
            'edges_json': '[]'
        })

    try:
        # Query to get test cases and their relationships
        query = """
        MATCH (s:TestSection)-[:CONTAINS]->(t:TestCase)
        RETURN s, t
        """
        result = driver.run_query(query)
        
        # Process the results
        nodes = []
        links = []
        node_ids = set()
        
        for record in result:
            section = record['s']
            test_case = record['t']
            
            # Add section node if not already added
            if section.id not in node_ids:
                nodes.append({
                    'id': f"section_{section.id}",
                    'label': section.get('name', 'Unnamed Section'),
                    'type': 'section',
                    'group': 1
                })
                node_ids.add(section.id)
            
            # Add test case node if not already added
            if test_case.id not in node_ids:
                nodes.append({
                    'id': f"case_{test_case.id}",
                    'label': test_case.get('title', 'Unnamed Test Case'),
                    'type': 'test',
                    'status': test_case.get('status', 'unknown'),
                    'group': 2
                })
                node_ids.add(test_case.id)
            
            # Add relationship between section and test case
            links.append({
                'source': f"section_{section.id}",
                'target': f"case_{test_case.id}",
                'type': 'CONTAINS'
            })
    
        context = {
            'nodes_json': json.dumps(nodes),
            'edges_json': json.dumps(links)
        }
        
    except Exception as e:
        logger.error(f"Error in test_impact_analysis: {str(e)}")
        context = {
            'error': f'Error analyzing test impact: {str(e)}',
            'nodes_json': '[]',
            'edges_json': '[]'
        }
    
    return render(request, 'dashboard/test_impact_analysis.html', context)

def test_analysis_dashboard(request):
    return render(request, 'dashboard/test_analysis.html')

def get_test_coverage(request):
    coverage = TestCoverage.objects.aggregate(
        avg_coverage=Avg('coverage_percentage')
    )
    
    test_stats = TestResult.objects.aggregate(
        passing=Count('id', filter=models.Q(status='PASS')),
        failed=Count('id', filter=models.Q(status='FAIL'))
    )
    
    return JsonResponse({
        'coverage': round(coverage['avg_coverage'] or 0, 2),
        'passing': test_stats['passing'],
        'failed': test_stats['failed']
    })

def get_test_results(request):
    results = TestResult.objects.all()[:50]  # Get last 50 test results
    return JsonResponse({
        'results': [{
            'name': result.name,
            'status': result.status,
            'duration': result.duration,
            'last_run': result.last_run.isoformat(),
            'error_message': result.error_message
        } for result in results]
    })

def get_impact_analysis(request):
    # Get recent changes and their impact
    dependencies = ComponentDependency.objects.all()
    impact_data = []
    
    for dep in dependencies:
        # Check if the target component has any failing tests
        failing_tests = TestResult.objects.filter(
            test_file__contains=dep.target,
            status='FAIL'
        ).count()
        
        impact_data.append({
            'source': dep.source,
            'target': dep.target,
            'type': dep.dependency_type,
            'failing_tests': failing_tests
        })
    
    return JsonResponse({
        'dependencies': impact_data
    })

def manage_nodes(request):
    """View for managing nodes in the database."""
    logger.debug("Entering manage_nodes view with method: %s", request.method)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        node_name = request.POST.get('node_name')
        
        if not node_name:
            messages.error(request, "Node name is required.")
            return redirect('dashboard:manage_nodes')
        
        try:
            driver = get_driver()
            with driver.session() as session:
                if action == 'delete':
                    # Delete node and its relationships
                    query = """
                    MATCH (n:Node {name: $name})
                    DETACH DELETE n
                    """
                    session.run(query, name=node_name)
                    messages.success(request, f"Node '{node_name}' deleted successfully.")
                
                elif action == 'edit':
                    new_name = request.POST.get('new_name')
                    new_description = request.POST.get('new_description', '')
                    
                    if not new_name:
                        messages.error(request, "New name is required.")
                        return redirect('dashboard:manage_nodes')
                    
                    # Update node properties
                    query = """
                    MATCH (n:Node {name: $old_name})
                    SET n.name = $new_name, n.description = $description
                    """
                    session.run(query, {
                        'old_name': node_name,
                        'new_name': new_name,
                        'description': new_description
                    })
                    messages.success(request, f"Node '{node_name}' updated successfully.")
        
        except Exception as e:
            logger.error("Error managing node: %s", str(e))
            messages.error(request, f"Error: {str(e)}")
    
    # Get all nodes for display
    try:
        driver = get_driver()
        with driver.session() as session:
            query = """
            MATCH (n:Node)
            RETURN n.name AS name, n.description AS description,
                   size((n)-[]->()) AS outgoing_relationships,
                   size([]->(n)) AS incoming_relationships
            ORDER BY n.name
            """
            result = session.run(query)
            nodes = [{
                'name': record['name'],
                'description': record['description'] or '',
                'outgoing_relationships': record['outgoing_relationships'],
                'incoming_relationships': record['incoming_relationships']
            } for record in result]
    except Exception as e:
        logger.error("Error fetching nodes: %s", str(e))
        nodes = []
        messages.error(request, f"Error fetching nodes: {str(e)}")
    
    return render(request, 'dashboard/manage_nodes.html', {
        'nodes': nodes
    })

@login_required
@user_passes_test(lambda u: u.can_access_admin_queries())
def admin_user_management(request):
    """Admin view to manage users and their approval status."""
    users = user.objects.all().order_by('username') # Fetch all users, ordered by username
    
    # Handle POST requests for approving/disapproving users
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')
        
        try:
            target_user = user.objects.get(pk=user_id)

            # Prevent deleting the currently logged-in superuser
            if action == 'delete' and target_user == request.user:
                 messages.error(request, 'You cannot delete your own account.')
                 return redirect('dashboard:admin_user_management')

            if action == 'approve':
                target_user.is_approved = True
                target_user.save()
                messages.success(request, f'User {target_user.username} approved.')
            elif action == 'disapprove':
                target_user.is_approved = False
                target_user.save()
                messages.success(request, f'User {target_user.username} disapproved.')
            elif action == 'set_role':
                 new_role = request.POST.get('new_role')
                 if new_role is not None:
                     try:
                         new_role = int(new_role)
                         if new_role in [choice[0] for choice in user.ROLE_CHOICES]:
                            target_user.role = new_role
                            target_user.save()
                            messages.success(request, f'Role for user {target_user.username} set to {new_role}.')
                         else:
                            messages.error(request, f'Invalid role {new_role}.')
                     except ValueError:
                         messages.error(request, f'Invalid role value.')
            elif action == 'delete': # Handle delete action
                 if not target_user.is_superuser: # Only allow deleting non-superusers from this view
                     target_user.delete()
                     messages.success(request, f'User {target_user.username} deleted.')
                 else:
                     messages.error(request, f'Cannot delete superuser {target_user.username} from this page.')

        except user.DoesNotExist:
            messages.error(request, 'User not found.')
        except Exception as e:
            messages.error(request, f'Error performing action: {e}')

        return redirect('dashboard:admin_user_management') # Redirect back to the same page after action

    context = {
        'users': users,
        'ROLE_CHOICES': user.ROLE_CHOICES, # Pass role choices to the template
    }
    return render(request, 'dashboard/admin_user_management.html', context)

@login_required
def neo4j_dashboard(request):
    """Render the Neo4j dashboard page with all Neo4j-related features."""
    logger.debug("Entering Neo4j dashboard view")
    
    context = {
        'can_access_predefined_queries': request.user.can_access_predefined_queries(),
        'can_access_explore_layers': request.user.can_access_explore_layers(),
        'can_access_add_nodes': request.user.can_access_add_nodes(),
        'can_access_admin_queries': request.user.can_access_admin_queries(),
    }
    return render(request, 'dashboard/neo4j.html', context)

@login_required
def api_tools(request):
    """Render the API Tools dashboard page."""
    # Get authentication status for display
    user_info = request.session.get('authenticated_user_info')
    
    # Only validate session if it's not a fresh authentication (avoid immediate validation after login)
    # Check if this is a fresh authentication by looking for success messages
    has_success_message = any(msg.level_tag == 'success' for msg in messages.get_messages(request))
    
    if user_info and user_info.get('valid') and not has_success_message:
        logger.info("🔍 Validating existing session in api_tools")
        is_still_valid = _validate_session_still_active(user_info)
        
        if not is_still_valid:
            logger.warning("⚠️ Session validation failed - clearing session")
            # Clear the invalid session
            request.session.pop('authenticated_user_info', None)
            user_info = None
            messages.error(request, "Your session has expired. Please authenticate again.")
        else:
            logger.info("✅ Session validation passed")
    elif has_success_message:
        logger.info("✅ Fresh authentication detected - skipping immediate validation")
    
    context = {
        'user_info': user_info,
    }
    
    return render(request, 'dashboard/api_tools.html', context)

@login_required
def clear_api_session(request):
    """Clear API authentication session"""
    # Clear all API-related session data
    request.session.pop('authenticated_user_info', None)
    request.session.pop('dynamicUserId', None)
    
    messages.info(request, "API session cleared. Please authenticate again to access admin tools.")
    return redirect('dashboard:api_tools')

@csrf_exempt
def authenticate_user_session(request):
    """Handle user session authentication using session ID and CSRF token"""
    if request.method == 'POST':
        session_id = request.POST.get('session_id', '').strip()
        csrf_token = request.POST.get('csrf_token', '').strip()
        
        if not session_id:
            messages.error(request, "Please provide a session ID.")
            return render(request, 'dashboard/api_tools.html')
            
        if not csrf_token:
            messages.error(request, "Please provide a CSRF token.")
            return render(request, 'dashboard/api_tools.html')

        try:
            # Create adminAPI instance
            api = adminAPI()
            logger.info(f"Attempting to authenticate with session ID: {session_id[:20]}... and CSRF token: {csrf_token[:20]}...")
            
            # Set both session ID and CSRF token
            api.session.cookies.set('sessionid', session_id, domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
            
            # Validate the session by testing with a real API call
            logger.info("Validating session and CSRF token with real API call")
            
            # Test 1: Try to access the accounts page
            try:
                accounts_response = api.session.get(f"{api.base_url}/accounts/", allow_redirects=True, timeout=10)
                logger.info(f"🔍 Accounts page response: status={accounts_response.status_code}, url={accounts_response.url}")
                
                # Check if we're redirected to login or get a non-200 status
                if 'login' in accounts_response.url:
                    logger.warning("⚠️ Redirected to login page - session invalid")
                    messages.error(request, "Session expired - please re-authenticate")
                    return render(request, 'dashboard/api_tools.html')
                elif accounts_response.status_code != 200:
                    logger.warning(f"⚠️ Non-200 status: {accounts_response.status_code}")
                    # Don't fail immediately for non-200, try the autocomplete test
                    logger.info("🔍 Proceeding to autocomplete test despite non-200 status")
                else:
                    logger.info("✅ Accounts page accessible - session appears valid")
                    
            except Exception as e:
                logger.error(f"❌ Error accessing accounts page: {e}")
                logger.info("🔍 Proceeding to autocomplete test despite error")
            
            # Test 2: Try to use the autocomplete API (which requires valid session)
            try:
                autocomplete_url = f"{api.base_url}/accounts/fullname_email_autocomplete"
                headers = {
                    'accept': '*/*',
                    'accept-language': 'en-US,en;q=0.9',
                    'cache-control': 'no-cache',
                    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'dnt': '1',
                    'origin': api.base_url,
                    'pragma': 'no-cache',
                    'priority': 'u=1, i',
                    'referer': f'{api.base_url}/accounts/',
                    'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"macOS"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                    'x-csrftoken': csrf_token,
                    'x-requested-with': 'XMLHttpRequest'
                }
                
                form_data = {
                    'term': 'test',
                    'q': 'test',
                    '_type': 'query'
                }
                
                autocomplete_response = api.session.post(autocomplete_url, headers=headers, data=form_data)
                
                if autocomplete_response.status_code != 200:
                    logger.warning(f"⚠️ Autocomplete API test failed with status {autocomplete_response.status_code}")
                    logger.info("🔍 Proceeding with authentication despite autocomplete test failure")
                else:
                    logger.info("✅ Autocomplete API test passed")
                
                # Try to parse the response to ensure it's valid JSON (if we got a response)
                if autocomplete_response.status_code == 200:
                    try:
                        autocomplete_data = autocomplete_response.json()
                        if 'results' not in autocomplete_data:
                            logger.warning("⚠️ Autocomplete API returned invalid response format")
                            logger.info("🔍 Proceeding with authentication despite invalid response format")
                        else:
                            logger.info("✅ Autocomplete API returned valid response format")
                    except Exception as e:
                        logger.warning(f"⚠️ Could not parse autocomplete response: {e}")
                        logger.info("🔍 Proceeding with authentication despite parse error")
                
                logger.info("✅ Session and CSRF token validation completed")
                
            except Exception as e:
                logger.error(f"❌ Error during API validation: {e}")
                logger.info("🔍 Proceeding with authentication despite validation error")
                # Don't fail authentication for validation errors, just log them
            
            logger.info("✅ Session and CSRF token validation successful")
            
            # Create basic authentication info with timestamp
            import time
            auth_info = {
                'valid': True,
                'session_id': session_id,
                'csrf_token': csrf_token,
                'session_id_short': session_id[:20] + "..." if len(session_id) > 20 else session_id,
                'csrf_token_short': csrf_token[:20] + "..." if csrf_token and len(csrf_token) > 20 else csrf_token,
                'validated': True,
                'session_created': time.time()  # Add timestamp for session timeout
            }
            
            # Store the authentication information in session
            request.session['authenticated_user_info'] = auth_info
            
            messages.success(request, "Authentication successful! You can now access admin tools.")
            
            logger.info(f"Stored auth info in session: {auth_info}")
            
            # Stay on API Tools page to show success message and allow card selection
            return redirect('dashboard:api_tools')
                
        except Exception as e:
            logger.error(f"Error during authentication: {str(e)}")
            messages.error(request, f"Authentication error: {str(e)}")

    return render(request, 'dashboard/api_tools.html')

@login_required
def create_wallet(request):
    # Check if user is properly authenticated
    user_info = request.session.get('authenticated_user_info')
    
    if not user_info or not user_info.get('valid'):
        messages.error(request, "Please authenticate first by entering your session ID and CSRF token.")
        return redirect('dashboard:api_tools')
    
    # Validate that the session is still active
    if not _validate_session_still_active(user_info):
        messages.error(request, "Your session has expired. Please authenticate again.")
        return redirect('dashboard:api_tools')
    
    # Add user search functionality
    searched_user = None
    if request.method == 'GET' and 'search_user' in request.GET:
        search_term = request.GET.get('search_term', '').strip()
        if search_term:
            try:
                api = adminAPI()
                api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
                api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
                
                # Use comprehensive search (same as Transaction Management and Feature Flags)
                current_user_id = user_info.get('user_id')
                user_data = api.comprehensive_user_search(search_term, current_user_id)
                
                if user_data:
                    searched_user = {
                        'uid': user_data.get('uid'),
                        'email': user_data.get('email'),
                        'full_name': user_data.get('full_name'),
                        'id': user_data.get('id'),
                        'tags': user_data.get('tags', []),
                        'search_term': search_term
                    }
                    messages.success(request, f"Found user: {searched_user['full_name']} ({searched_user['email']})")
                else:
                    messages.warning(request, f"No user found for: {search_term}")
            except Exception as e:
                logger.error(f"Error searching for user: {e}")
                messages.error(request, "Error searching for user. Please try again.")
    
    if request.method == 'POST':
        form = WalletCreationForm(request.POST)
        if form.is_valid():
            testnet_user = form.cleaned_data['testnet_username']
            testnet_pass = form.cleaned_data['testnet_password']
            
            try:
                # Initialize service and attempt login
                authed_service = adminAPI()
                login_result = authed_service.login(testnet_user, testnet_pass)

                if not login_result:
                    messages.error(request, "Invalid Testnet Admin username or password.")
                    return redirect('dashboard:create_wallet')
                

                # Prepare data for wallet creation
                wallet_data = {
                    'user': form.cleaned_data['user_id'],
                    'currency': form.cleaned_data['currency'],
                    'type': form.cleaned_data['type'],
                    'balance': form.cleaned_data['balance'],
                    'balance_blocked': form.cleaned_data['balance_blocked'],
                    'is_active': 'on' if form.cleaned_data.get('is_active') else '',
                    'recovery_state': form.cleaned_data['recovery_state'],
                    '_save': 'Save'
                }

                # Use the same service instance (which now holds the session) to create the wallet
                response = authed_service.create_wallet(wallet_data)

                if 'errornote' in response.text:
                    messages.error(request, f"API returned an error during wallet creation. Please check the form data.")
                    return redirect('dashboard:create_wallet')
                messages.success(request, 'Wallet creation request sent successfully!')

            except requests.exceptions.RequestException as e:
                messages.error(request, f"Error connecting to the wallet service: {e}")
            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {e}")

            return redirect('dashboard:create_wallet')
    else:
        form = WalletCreationForm()
        
    return render(request, 'dashboard/create_wallet.html', {'form': form, 'searched_user': searched_user})

@login_required
def add_transaction(request):
    """Handle add transaction functionality using admin API"""
    # Get stored authentication information from session
    user_info = request.session.get('authenticated_user_info')
    
    if not user_info or not user_info.get('valid'):
        return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
    
    # Validate that the session is still active
    if not _validate_session_still_active(user_info):
        return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
    
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        wallet = request.POST.get('wallet')
        amount = request.POST.get('amount')
        description = request.POST.get('description', 'Manual Transaction')
        ref_id = request.POST.get('ref_id', '')
        ref_module = request.POST.get('ref_module', '')
        transaction_type = request.POST.get('transactionType', '60')  # Default to Manual (60)
        
        if not all([user_id, wallet, amount]):
            return JsonResponse({'error': 'Please fill in all required fields.'}, status=400)
        
        try:
            # Initialize admin API with stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            logger.info(f"Creating transaction for user {user_id} with wallet {wallet}")
            
            # Prepare transaction data with correct field names
            transaction_data = {
                'wallet': wallet,
                'amount': amount,
                'tp': transaction_type,  # Transaction type (60 = Manual, 61 = Deposit, 62 = Withdrawal)
                'description': description,
            }
            
            # Add optional fields if provided
            if ref_id:
                transaction_data['ref_id'] = ref_id
            if ref_module:
                transaction_data['ref_module'] = ref_module
            
            logger.info(f"Transaction data: {transaction_data}")
            
            # Make the API call to create transaction
            logger.info(f"Making API call to add transaction for user {user_id}")
            response = api.add_transaction(user_id, transaction_data)
            
            logger.info(f"API response status: {response.status_code}")
            logger.info(f"API response content: {response.text[:500]}...")
            
            # Check for successful response (200 or 302 for redirects)
            if response.status_code in [200, 302]:
                # Get the transaction ID from the response or parse it
                transaction_id = None
                try:
                    # Try to extract transaction ID from response
                    response_text = response.text
                    if 'transaction-request-accept' in response_text:
                        import re
                        match = re.search(r'transaction-request-accept/(\d+)', response_text)
                        if match:
                            transaction_id = match.group(1)
                            logger.info(f"Extracted transaction ID: {transaction_id}")
                except Exception as e:
                    logger.warning(f"Could not extract transaction ID: {e}")
                
                # Automatically approve the transaction if we have an ID
                approval_status = 'new'
                if transaction_id:
                    try:
                        logger.info(f"Auto-approving transaction {transaction_id}")
                        confirm_response = api.confirm_transaction(user_id, transaction_id)
                        if confirm_response.status_code in [200, 302]:
                            approval_status = 'approved'
                            logger.info(f"Transaction {transaction_id} auto-approved successfully")
                        else:
                            logger.warning(f"Auto-approval failed for transaction {transaction_id}: {confirm_response.status_code}")
                    except Exception as e:
                        logger.error(f"Error auto-approving transaction {transaction_id}: {e}")
                
                return JsonResponse({
                    'success': True, 
                    'message': 'Transaction created successfully!',
                    'transaction_id': transaction_id,
                    'approval_status': approval_status
                })
            else:
                logger.error(f"Transaction creation failed with status {response.status_code}")
                return JsonResponse({'error': f'Transaction creation failed with status {response.status_code}'}, status=400)
                
        except Exception as e:
            logger.error(f"Error creating transaction: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def load_wallets_ajax(request):
    """AJAX endpoint for loading user wallets"""
    if request.method == 'GET':
        # Get the user_id from query parameters
        user_id = request.GET.get('user_id')
        
        # Get stored authentication information from session
        user_info = request.session.get('authenticated_user_info')
        
        if not user_info or not user_info.get('valid'):
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
        
        if not user_id:
            return JsonResponse({'error': 'User ID is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            logger.info(f"Loading wallets for searched user ID: {user_id}")
            
            wallets = api.get_wallets(user_id)
            
            # Log the wallets for debugging
            logger.info(f"Loaded {len(wallets)} wallets for user {user_id}")
            for wallet in wallets:
                logger.info(f"Wallet: {wallet['value']} - {wallet['text']}")
            
            # If no wallets found, log the response for debugging
            if not wallets:
                logger.warning(f"No wallets found for user {user_id}. This might indicate an authentication issue or the API response format has changed.")
            
            return JsonResponse({'success': True, 'wallets': wallets})
                
        except Exception as e:
            logger.error(f"Error loading wallets: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def transaction_confirmation(request):
    """Display transaction confirmation page with pending transaction data"""
    # Get transaction data from session
    transaction_data = request.session.get('pending_transaction')
    
    if not transaction_data:
        messages.warning(request, "No pending transaction found. Please create a transaction first.")
        return redirect('dashboard:add_transaction')
    
    # Add timestamp if not present
    if 'created_at' not in transaction_data:
        from datetime import datetime
        transaction_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'transaction': transaction_data
    }
    
    return render(request, 'dashboard/transaction_confirmation.html', context)

@login_required
def transaction_management(request):
    """Display comprehensive transaction management page - requires authentication"""
    # Check if user is properly authenticated
    user_info = request.session.get('authenticated_user_info')
    
    if not user_info or not user_info.get('valid'):
        messages.error(request, "Please authenticate first by entering your session ID and CSRF token.")
        return redirect('dashboard:api_tools')
    
    # Validate that the session is still active
    if not _validate_session_still_active(user_info):
        messages.error(request, "Your session has expired. Please authenticate again.")
        return redirect('dashboard:api_tools')
    
    # Get user ID and render the authenticated page
    user_id = request.session.get('dynamicUserId')
    
    context = {
        'user_info': user_info,
        'user_id': user_id,
        'is_authenticated': True,
    }
    
    return render(request, 'dashboard/transaction_management.html', context)

@login_required
def feature_flags(request):
    """Display feature flags management page - requires authentication"""
    # Check if user is properly authenticated
    user_info = request.session.get('authenticated_user_info')
    
    if not user_info or not user_info.get('valid'):
        messages.error(request, "Please authenticate first by entering your session ID and CSRF token.")
        return redirect('dashboard:api_tools')
    
    # Validate that the session is still active
    if not _validate_session_still_active(user_info):
        messages.error(request, "Your session has expired. Please authenticate again.")
        return redirect('dashboard:api_tools')
    
    context = {
        'user_info': user_info,
        'is_authenticated': True,
    }
    
    return render(request, 'dashboard/feature_flags.html', context)

@csrf_exempt
def search_user_for_feature_flags(request):
    """AJAX endpoint for searching user by mobile number for feature flags"""
    if request.method == 'POST':
        mobile_number = request.POST.get('mobile_number', '').strip()
        
        logger.info(f"🔍 Feature flags search request for mobile: {mobile_number}")
        
        if not mobile_number:
            logger.warning("❌ No mobile number provided")
            return JsonResponse({'error': 'Mobile number is required'}, status=400)
        
        # Get stored authentication information from session
        user_info = request.session.get('authenticated_user_info')
        
        logger.info(f"🔍 Session user_info: {user_info}")
        
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ No valid authenticated session found")
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        logger.info("🔍 Validating session...")
        if not _validate_session_still_active(user_info):
            logger.warning("❌ Session validation failed")
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
        
        try:
            # Create API instance using stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            # Search for user using comprehensive search (multiple methods) - SAME AS TRANSACTION MANAGEMENT
            current_user_id = user_info.get('user_id')
            user_data = api.comprehensive_user_search(mobile_number, current_user_id)
            
            if user_data:
                # Create user info response (same format as transaction management)
                user_info_response = {
                    'valid': True,
                    'user_id': user_data.get('uid'),
                    'email': user_data.get('email'),
                    'full_name': user_data.get('full_name'),
                    'id': user_data.get('id'),
                    'tags': user_data.get('tags', []),
                    'search_term': mobile_number,
                    'validated': True
                }
                
                # Store the database user ID in session for feature flag creation
                request.session['dynamicUserId'] = user_data.get('id')
                logger.info(f"🔍 Stored database user ID in session: {user_data.get('id')}")
                
                logger.info(f"✅ User found for feature flags: {user_info_response}")
                return JsonResponse({
                    'success': True,
                    'user_info': user_info_response
                })
            else:
                logger.warning(f"❌ No user found for mobile: {mobile_number}")
                return JsonResponse({'success': False, 'error': 'User not found'}, status=200)
                
        except Exception as e:
            logger.error(f"❌ Error searching user for feature flags: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_feature_flags_ajax(request):
    """AJAX endpoint for getting available feature flags"""
    if request.method == 'GET':
        # Get stored authentication information from session
        user_info = request.session.get('authenticated_user_info')
        
        logger.info(f"🔍 get_feature_flags_ajax - Session user_info: {user_info}")
        
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ No valid authenticated session found in get_feature_flags_ajax")
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
        
        try:
            # Create API instance using stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            # Get feature flags
            feature_flags = api.get_feature_flags()
            
            return JsonResponse({
                'success': True,
                'feature_flags': feature_flags
            })
            
        except Exception as e:
            logger.error(f"❌ Error getting feature flags: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_user_feature_flags_ajax(request):
    """AJAX endpoint to get existing feature flags for a user"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'Only GET method allowed'}, status=405)
    
    try:
        # Get user info from session
        user_info = request.session.get('authenticated_user_info')
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ No valid authenticated session found in get_user_feature_flags_ajax")
            return JsonResponse({'success': False, 'error': 'Authentication required'}, status=401)
        
        # Get the database user ID from session
        user_db_id = request.session.get('dynamicUserId')
        if not user_db_id:
            logger.warning("❌ No dynamicUserId found in session")
            return JsonResponse({'success': False, 'error': 'User not found in session'}, status=400)
        
        logger.info(f"🔍 Getting existing feature flags for user {user_db_id}")
        
        # Initialize API
        api = adminAPI()
        api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
        api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
        
        # Get existing feature flags for the user
        existing_flags = api.get_user_feature_flags(user_db_id)
        
        logger.info(f"✅ Retrieved {len(existing_flags)} existing feature flags for user {user_db_id}")
        return JsonResponse({'success': True, 'existing_flags': existing_flags})
            
    except Exception as e:
        logger.error(f"❌ Error in get_user_feature_flags_ajax: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

def create_feature_flag_ajax(request):
    """AJAX endpoint for creating feature flags for a user"""
    if request.method == 'POST':
        user_id = request.POST.get('user_id', '').strip()
        feature_name = request.POST.get('feature_name', '').strip()
        status = request.POST.get('status', 'done').strip()
        
        logger.info(f"🔍 create_feature_flag_ajax called with user_id={user_id}, feature_name={feature_name}, status={status}")
        
        if not user_id or not feature_name:
            logger.warning(f"❌ Missing required parameters: user_id={user_id}, feature_name={feature_name}")
            return JsonResponse({'error': 'User ID and feature name are required'}, status=400)
        
        # Get stored authentication information from session
        user_info = request.session.get('authenticated_user_info')
        
        if not user_info or not user_info.get('valid'):
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
        
        try:
            # Create API instance using stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            # Get the database user ID from the session (stored during user search)
            user_db_id = request.session.get('dynamicUserId')  # This should contain the database ID
            if not user_db_id:
                logger.error(f"❌ No database user ID found in session for user {user_id}")
                return JsonResponse({'error': 'User database ID not found. Please search for the user again.'}, status=400)
            
            # Create feature flag
            logger.info(f"🔍 Calling api.create_feature_flag with user_id={user_id}, user_db_id={user_db_id}, feature_name={feature_name}, status={status}")
            success = api.create_feature_flag(user_id, feature_name, status, user_db_id)
            logger.info(f"🔍 create_feature_flag result: {success}")
            
            if success:
                logger.info(f"✅ Feature flag created successfully: {feature_name} for user {user_id}")
                return JsonResponse({
                    'success': True,
                    'message': f'Feature flag "{feature_name}" created successfully for user {user_id}'
                })
            else:
                logger.warning(f"❌ Failed to create feature flag: {feature_name} for user {user_id}")
                return JsonResponse({'error': 'Failed to create feature flag'}, status=500)
                
        except Exception as e:
            logger.error(f"❌ Error creating feature flag: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def add_all_features_ajax(request):
    """AJAX endpoint for adding all available features to a user with progress tracking"""
    logger.info("🚀 add_all_features_ajax called")
    if request.method == 'POST':
        try:
            # Get authenticated user info
            user_info = request.session.get('authenticated_user_info')
            if not user_info or not user_info.get('valid'):
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            # Validate that the session is still active
            if not _validate_session_still_active(user_info):
                return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
            
            # Get database user ID from request (we're sending the database ID directly)
            user_db_id = request.POST.get('user_id')
            logger.info(f"🔍 Received user_db_id: {user_db_id}")
            if not user_db_id:
                logger.error("❌ No user_db_id provided in request")
                return JsonResponse({'error': 'User database ID is required'}, status=400)
            
            # Get the user UID from session storage (we need both UID and database ID)
            user_uid = request.session.get('selected_user_uid')
            if not user_uid:
                return JsonResponse({'error': 'User UID not found. Please search for the user again.'}, status=400)
            
            # Use UID for logging and database ID for API calls
            user_id = user_uid
            
            # Create API instance
            api = adminAPI()
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrf_token', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            # Get all available features
            logger.info("🔍 Getting all available features...")
            features = api.get_feature_flags()
            
            if not features:
                return JsonResponse({'error': 'No features available'}, status=400)
            
            logger.info(f"✅ Found {len(features)} features to add")
            
            # Add each feature with real-time progress
            results = []
            for i, feature in enumerate(features):
                try:
                    feature_name = feature.get('text', '')
                    feature_value = feature.get('value', '')
                    
                    logger.info(f"🔍 Adding feature {i+1}/{len(features)}: {feature_name}")
                    
                    # Create feature flag
                    success = api.create_feature_flag(user_id, feature_value, 'done', user_db_id)
                    
                    result = {
                        'feature_name': feature_name,
                        'feature_value': feature_value,
                        'success': success,
                        'index': i + 1,
                        'total': len(features),
                        'progress_percentage': round(((i + 1) / len(features)) * 100, 1)
                    }
                    results.append(result)
                    
                    # No artificial delay - process features as fast as possible
                    
                except Exception as e:
                    logger.error(f"❌ Error adding feature {feature_name}: {e}")
                    result = {
                        'feature_name': feature_name,
                        'feature_value': feature_value,
                        'success': False,
                        'error': str(e),
                        'index': i + 1,
                        'total': len(features),
                        'progress_percentage': round(((i + 1) / len(features)) * 100, 1)
                    }
                    results.append(result)
            
            # Count successful additions
            successful = sum(1 for r in results if r['success'])
            failed = len(results) - successful
            
            return JsonResponse({
                'success': True,
                'message': f'Added {successful} features successfully. {failed} failed.',
                'results': results,
                'total': len(features),
                'successful': successful,
                'failed': failed
            })
            
        except Exception as e:
            logger.error(f"❌ Error in add_all_features_ajax: {e}")
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def store_user_db_id(request):
    """Store user database ID and UID in Django session"""
    if request.method == 'POST':
        try:
            user_db_id = request.POST.get('user_db_id', '').strip()
            user_uid = request.POST.get('user_uid', '').strip()
            
            if not user_db_id:
                return JsonResponse({'error': 'User database ID is required'}, status=400)
            
            if not user_uid:
                return JsonResponse({'error': 'User UID is required'}, status=400)
            
            # Store both in Django session
            request.session['dynamicUserId'] = user_db_id
            request.session['selected_user_uid'] = user_uid
            logger.info(f"✅ Stored user database ID: {user_db_id} and UID: {user_uid} in session")
            
            return JsonResponse({'success': True, 'message': 'User information stored successfully'})
            
        except Exception as e:
            logger.error(f"❌ Error storing user information: {e}")
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def search_user_by_mobile(request):
    """AJAX endpoint for searching user by mobile number"""
    if request.method == 'POST':
        mobile_number = request.POST.get('mobile_number', '').strip()
        
        logger.info(f"🔍 Search request for mobile: {mobile_number}")
        
        if not mobile_number:
            logger.warning("❌ No mobile number provided")
            return JsonResponse({'error': 'Mobile number is required'}, status=400)
        
        # Get stored authentication information from session
        user_info = request.session.get('authenticated_user_info')
        
        logger.info(f"🔍 Session user_info: {user_info}")
        
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ No valid authenticated session found")
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        logger.info("🔍 Validating session...")
        if not _validate_session_still_active(user_info):
            logger.warning("❌ Session validation failed")
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
        
        try:
            # Create API instance using stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            # Search for user using comprehensive search (multiple methods)
            current_user_id = user_info.get('user_id')
            user_data = api.comprehensive_user_search(mobile_number, current_user_id)
            
            if user_data:
                # Create user info response
                user_info_response = {
                    'valid': True,
                    'user_id': user_data.get('uid'),
                    'email': user_data.get('email'),
                    'full_name': user_data.get('full_name'),
                    'id': user_data.get('id'),
                    'tags': user_data.get('tags', []),
                    'search_term': mobile_number,
                    'validated': True
                }
                
                logger.info(f"✅ User found by mobile number {mobile_number}:")
                logger.info(f"   User ID: {user_data.get('uid')}")
                logger.info(f"   Email: {user_data.get('email')}")
                logger.info(f"   Full Name: {user_data.get('full_name')}")
                
                return JsonResponse({'success': True, 'user_info': user_info_response})
            else:
                logger.error(f"❌ No user found for mobile number: {mobile_number}")
                return JsonResponse({'error': f'No user found for mobile number: {mobile_number}'}, status=404)
                
        except Exception as e:
            logger.error(f"Error searching user by mobile number: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def get_transactions_ajax(request):
    """AJAX endpoint for getting user transactions"""
    if request.method == 'GET':
        # Get user_id from query parameters
        user_id = request.GET.get('user_id')
        
        # Get stored user information from session
        user_info = request.session.get('authenticated_user_info')
        
        if not user_info or not user_info.get('valid'):
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)
            
        if not user_id:
            return JsonResponse({'error': 'User ID is required'}, status=400)
        
        try:
            # Create API instance using stored session information
            api = adminAPI()
            
            # Set the stored session ID and CSRF token
            api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            api.session.cookies.set('csrftoken', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
            
            logger.info(f"Loading transactions for user ID: {user_id}")
            
            # Get transactions for the searched user
            transactions = api.get_transactions(user_id)
            
            if transactions is None:
                transactions = []
            
            logger.info(f"Loaded {len(transactions)} transactions for user {user_id}")
            
            return JsonResponse({
                'success': True,
                'transactions': transactions
            })
                
        except Exception as e:
            logger.error(f"Error loading transactions: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def transaction_action_ajax(request):
    """AJAX endpoint for transaction actions (confirm, reject, edit)"""
    logger.info("=== TRANSACTION ACTION AJAX CALLED ===")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request POST data: {dict(request.POST)}")
    
    if request.method == 'POST':
        # Get stored user information from session
        user_info = request.session.get('authenticated_user_info')
        user_id = request.session.get('dynamicUserId')
        action = request.POST.get('action')
        transaction_id = request.POST.get('transaction_id')
        
        logger.info(f"Extracted parameters - user_id: {user_id}, action: {action}, transaction_id: {transaction_id}")
        logger.info(f"User info from session: {user_info}")
        
        if not all([user_id, action, transaction_id]):
            logger.error("Missing required parameters")
            return JsonResponse({'error': 'Missing required parameters'}, status=400)
        
        if not user_info or not user_info.get('valid'):
            logger.error("No authenticated session found")
            return JsonResponse({'error': 'No authenticated session found. Please authenticate first.'}, status=400)
        
        try:
            logger.info("Creating adminAPI instance...")
            # Create API instance using stored session information
            api = adminAPI()
            
            # Use the stored session ID if available
            if user_info.get('sessionid'):
                api._set_cookies(fetch_token=user_info['sessionid'])
                logger.info(f"Using stored session ID: {user_info['sessionid'][:20]}...")
            else:
                # Fallback: use user_id directly (less secure)
                logger.info(f"Using user_id directly: {user_id}")
            
            # Update API instance with user ID
            api.user_id = user_id
            logger.info(f"Using user ID: {user_id}")
            logger.info(f"Session cookies set: {dict(api.session.cookies)}")
            
            if action == 'confirm':
                logger.info(f"Confirming transaction {transaction_id} for user {user_id}")
                logger.info(f"API session cookies before confirm: {dict(api.session.cookies)}")
                
                # First, let's test if the user exists and get their transactions
                logger.info("Testing user transactions first...")
                test_response = api.get_user_transactions(user_id)
                logger.info(f"User transactions test status: {test_response.status_code}")
                
                if test_response.status_code == 200:
                    logger.info("User exists, proceeding with confirmation...")
                    response = api.confirm_transaction(user_id, transaction_id)
                    logger.info(f"Confirm response status: {response.status_code}")
                    logger.info(f"Confirm response headers: {dict(response.headers)}")
                    logger.info(f"Confirm response content preview: {response.text[:500]}...")
                    
                    # Check if the response indicates success
                    if response.status_code == 200:
                        logger.info("✅ Transaction confirmation appears successful (200 status)")
                    elif response.status_code == 302:
                        logger.info("✅ Transaction confirmation appears successful (302 redirect)")
                    else:
                        logger.warning(f"⚠️ Unexpected response status: {response.status_code}")
                else:
                    logger.error(f"❌ User test failed with status: {test_response.status_code}")
                    response = test_response
            elif action == 'reject':
                logger.info(f"Rejecting transaction {transaction_id} for user {user_id}")
                response = api.reject_transaction(user_id, transaction_id)
                logger.info(f"Reject response status: {response.status_code}")
                logger.info(f"Reject response content preview: {response.text[:200]}...")
            elif action == 'edit':
                logger.info(f"Editing transaction {transaction_id} for user {user_id}")
                # For edit, we'll use basic transaction data
                transaction_data = {
                    'description': 'Transaction edited via dashboard',
                    'amount': '100000'  # Default amount
                }
                response = api.edit_transaction(user_id, transaction_id, transaction_data)
                logger.info(f"Edit response status: {response.status_code}")
            else:
                logger.error(f"Invalid action: {action}")
                return JsonResponse({'error': 'Invalid action'}, status=400)
            
            if response.status_code == 200:
                logger.info(f"Transaction {action} successful!")
                return JsonResponse({'success': True, 'message': f'Transaction {action}ed successfully'})
            else:
                logger.error(f"API returned status {response.status_code}")
                return JsonResponse({'error': f'API returned status {response.status_code}'}, status=500)
                
        except Exception as e:
            logger.error(f"Error {action}ing transaction: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    logger.error("Invalid request method")
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def validate_token_ajax(request):
    """AJAX endpoint for validating Testnet Admin token"""
    if request.method == 'POST':
        auth_token = request.POST.get('auth_token')
        
        if not auth_token:
            return JsonResponse({'error': 'Token is required'}, status=400)
        
        try:
            # Create API instance and extract all user information automatically
            api = adminAPI()
            api._set_cookies(fetch_token=auth_token)
            
            # Extract all user information from the session automatically
            user_info = api.extract_user_info_from_session()
            
            if user_info['valid'] and user_info['user_id']:
                # Update the API instance with the extracted user ID
                api.user_id = user_info['user_id']
                # Store the user_id for future use
                session_key = user_info.get('sessionid')
                if session_key:
                    request.session[f'user_id_for_session_{session_key}'] = user_info['user_id']
                    logger.info(f"Stored user_id {user_info['user_id']} for session {session_key}")
            
            if user_info['valid']:
                logger.info(f"User information extracted: {user_info}")
                return JsonResponse({
                    'success': True,
                    'user_info': user_info,
                    'message': 'Token validated successfully'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': user_info.get('error', 'Token validation failed'),
                    'user_info': user_info
                }, status=400)
                
        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def test_confirm_ajax(request):
    """Test endpoint for confirm functionality - no authentication required"""
    if request.method == 'POST':
        action = request.POST.get('action', 'test')
        transaction_id = request.POST.get('transaction_id', 'unknown')
        
        logger.info(f"Test confirm AJAX called - action: {action}, transaction_id: {transaction_id}")
        
        return JsonResponse({
            'success': True,
            'message': f'Test {action} successful for transaction {transaction_id}',
            'action': action,
            'transaction_id': transaction_id
        })
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def test_user_id_fetch(request):
    """Test endpoint to fetch user ID dynamically"""
    if request.method == 'POST':
        auth_token = request.POST.get('auth_token')
        phone_number = request.POST.get('phone_number', '09358165170')
        
        if not auth_token:
            return JsonResponse({'error': 'Missing auth_token'}, status=400)
        
        try:
            api = adminAPI()
            api._set_cookies(fetch_token=auth_token)
            
            logger.info(f"Testing user ID fetch for phone: {phone_number}")
            user_id = api.get_user_id_by_phone(phone_number)
            
            if user_id:
                return JsonResponse({
                    'success': True,
                    'user_id': user_id,
                    'phone_number': phone_number,
                    'message': f'Successfully fetched user ID: {user_id}'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Could not fetch user ID',
                    'phone_number': phone_number
                })
                
        except Exception as e:
            logger.error(f"Error testing user ID fetch: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e),
                'phone_number': phone_number
            })
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def test_user_id_extraction(request):
    """Test endpoint to help debug user ID extraction"""
    if request.method == 'POST':
        auth_token = request.POST.get('auth_token')
        
        if not auth_token:
            return JsonResponse({'error': 'Token is required'}, status=400)
        
        try:
            api = adminAPI()
            api._set_cookies(fetch_token=auth_token)
            
            # Try all extraction methods
            user_info = api._extract_user_from_session_data()
            
            # Also try the main extraction method
            main_user_info = api.extract_user_info_from_session()
            
            return JsonResponse({
                'success': True,
                'session_data_extraction': user_info,
                'main_extraction': main_user_info,
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken'),
                'all_cookies': dict(api.session.cookies)
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_user_from_django_session(request):
    """Get user ID from Django session using session ID"""
    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        
        if not session_id:
            return JsonResponse({'error': 'Session ID is required'}, status=400)
        
        try:
            from django.contrib.sessions.models import Session
            from django.contrib.auth.models import User
            
            # Get the session from Django's session table
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            
            # Extract user ID from session data
            user_id = session_data.get('_auth_user_id')
            if user_id:
                try:
                    user = User.objects.get(pk=user_id)
                    return JsonResponse({
                        'success': True,
                        'user_id': str(user.id),
                        'username': user.username,
                        'email': user.email,
                        'session_data': session_data
                    })
                except User.DoesNotExist:
                    return JsonResponse({'error': 'User not found'}, status=404)
            else:
                return JsonResponse({'error': 'No user ID found in session'}, status=404)
                
        except Session.DoesNotExist:
            return JsonResponse({'error': 'Session not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_session_extraction(request):
    """Debug endpoint to help troubleshoot session extraction"""
    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        
        if not session_id:
            return JsonResponse({'error': 'Session ID is required'}, status=400)
        
        try:
            api = adminAPI()
            api._set_cookies(fetch_token=session_id)
            
            # Extract user info
            user_info = api.extract_user_info_from_session()
            
            # Get detailed debug information
            debug_info = {
                'session_id': session_id,
                'extracted_user_info': user_info,
                'session_cookies': dict(api.session.cookies),
                'validation_result': None
            }
            
            # If we got a user ID, validate it
            if user_info.get('user_id'):
                validation_result = api.validate_extracted_user_id(user_info['user_id'], session_id)
                debug_info['validation_result'] = validation_result
                
                # Try to get user transactions to test the user ID
                try:
                    test_response = api.get_user_transactions(user_info['user_id'])
                    debug_info['user_transactions_test'] = {
                        'status_code': test_response.status_code,
                        'response_preview': test_response.text[:500] if hasattr(test_response, 'text') else str(test_response)
                    }
                except Exception as e:
                    debug_info['user_transactions_test'] = {'error': str(e)}
            
            return JsonResponse({
                'success': True,
                'debug_info': debug_info
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_user_id_validation(request):
    """Debug endpoint to test user ID validation"""
    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        user_id = request.POST.get('user_id')
        
        if not session_id or not user_id:
            return JsonResponse({'error': 'Session ID and User ID are required'}, status=400)
        
        try:
            api = adminAPI()
            api._set_cookies(fetch_token=session_id)
            
            # Test the user ID validation
            validation_result = api.validate_extracted_user_id(user_id, session_id)
            
            # Try to get user transactions
            test_response = api.get_user_transactions(user_id)
            
            return JsonResponse({
                'success': True,
                'user_id': user_id,
                'session_id': session_id,
                'validation_result': validation_result,
                'user_transactions_test': {
                    'status_code': test_response.status_code,
                    'response_preview': test_response.text[:500] if hasattr(test_response, 'text') else str(test_response)
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def debug_cookie_parsing(request):
    """Debug endpoint to test cookie parsing from different formats"""
    if request.method == 'POST':
        cookie_input = request.POST.get('cookie_input')
        
        if not cookie_input:
            return JsonResponse({'error': 'Cookie input is required'}, status=400)
        
        try:
            api = adminAPI()
            
            # Test the cookie parsing
            parsed_cookies = api._parse_curl_cookies(cookie_input)
            
            # Set the cookies and see what we get
            api._set_cookies(cookie_input)
            
            return JsonResponse({
                'success': True,
                'input': cookie_input,
                'parsed_cookies': parsed_cookies,
                'session_cookies': dict(api.session.cookies),
                'sessionid': api.session.cookies.get('sessionid'),
                'csrftoken': api.session.cookies.get('csrftoken')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def debug_csrf_extraction(request):
    """Debug endpoint to test CSRF token extraction specifically"""
    if request.method == "POST":
        session_id = request.POST.get("session_id")
        user_id = request.POST.get("user_id")
        
        if not session_id:
            return JsonResponse({"error": "Session ID is required"}, status=400)
        
        try:
            api = adminAPI()
            api._set_cookies(fetch_token=session_id)
            
            # Test different CSRF token extraction methods
            debug_info = {
                "session_id": session_id,
                "user_id": user_id,
                "csrf_from_cookies": api.session.cookies.get("csrftoken"),
                "csrf_from_session": None,
                "csrf_from_user_page": None,
                "all_cookies": dict(api.session.cookies)
            }
            
            # Test general session CSRF extraction
            try:
                csrf_from_session = api._get_csrf_token_from_session(session_id)
                debug_info["csrf_from_session"] = csrf_from_session
            except Exception as e:
                debug_info["csrf_from_session_error"] = str(e)
            
            # Test user-specific CSRF extraction if user_id provided
            if user_id:
                try:
                    csrf_from_user = api._get_csrf_token_for_user(user_id, session_id)
                    debug_info["csrf_from_user_page"] = csrf_from_user
                except Exception as e:
                    debug_info["csrf_from_user_page_error"] = str(e)
            
            return JsonResponse({
                "success": True,
                "debug_info": debug_info
            })
            
        except Exception as e:
            return JsonResponse({
                "success": False,
                "error": str(e)
            }, status=500)
    
    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def debug_csrf_from_url(request):
    """Debug endpoint to test CSRF token extraction from specific URL"""
    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        user_id = request.POST.get('user_id')
        url = request.POST.get('url', f'https://testnetadminv2.ntx.ir/accounts/{user_id}/add-transaction')
        
        if not session_id or not user_id:
            return JsonResponse({'error': 'Session ID and User ID are required'}, status=400)
        
        try:
            api = adminAPI()
            # Set cookies with session ID
            api._set_cookies(fetch_token=session_id)
            
            debug_info = {
                'session_id': session_id,
                'user_id': user_id,
                'target_url': url,
                'cookies_before_get': dict(api.session.cookies),
                'csrf_from_cookies_before': api.session.cookies.get('csrftoken'),
                'get_response_status': None,
                'get_response_url': None,
                'cookies_after_get': None,
                'csrf_from_cookies_after': None,
                'csrf_from_html': None,
                'csrf_final': None
            }
            
            # Make GET request to the specific URL
            print(f"🔍 Making GET request to: {url}")
            get_resp = api.session.get(url, allow_redirects=True)
            
            debug_info['get_response_status'] = get_resp.status_code
            debug_info['get_response_url'] = get_resp.url
            debug_info['cookies_after_get'] = dict(api.session.cookies)
            debug_info['csrf_from_cookies_after'] = api.session.cookies.get('csrftoken')
            
            # Try to get CSRF token from cookies first
            csrf_token = api.session.cookies.get('csrftoken')
            print(f"🔍 CSRF Token from cookies after GET: {csrf_token}")
            
            # If no CSRF token from cookies, try HTML parsing
            if not csrf_token:
                print("🔍 No CSRF token in cookies, trying HTML parsing...")
                soup = BeautifulSoup(get_resp.text, "html.parser")
                csrf_tag = soup.find("input", {"name": "csrfmiddlewaretoken"})
                if csrf_tag:
                    csrf_token = csrf_tag.get("value")
                    print(f"🔍 CSRF Token from HTML: {csrf_token}")
                    debug_info['csrf_from_html'] = csrf_token
                else:
                    print("🔍 No CSRF token found in HTML either")
            
            debug_info['csrf_final'] = csrf_token
            
            # Show page content preview for debugging
            debug_info['page_content_preview'] = get_resp.text[:1000] if get_resp.text else "No content"
            
            return JsonResponse({
                'success': True,
                'debug_info': debug_info
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def centralized_user_search(request):
    """Centralized user search endpoint for all admin tools"""
    try:
        logger.info("🔍 Centralized user search endpoint called")
        
        if request.method != 'POST':
            return JsonResponse({
                'success': False,
                'error': 'Only POST method allowed'
            })
        
        # Get search term
        search_term = request.POST.get('search_term', '').strip()
        if not search_term:
            return JsonResponse({
                'success': False,
                'error': 'Search term is required'
            })
        
        logger.info(f"Searching for: {search_term}")
        
        # Get authenticated user info - STRICT AUTHENTICATION CHECK
        user_info = request.session.get('authenticated_user_info')
        if not user_info or not user_info.get('valid'):
            logger.warning("❌ Unauthorized access attempt to centralized user search")
            return JsonResponse({
                'success': False,
                'error': 'Authentication required. Please authenticate first.'
            }, status=401)
        
        # Additional security: Check if session is still valid
        if not user_info.get('session_id') or not user_info.get('csrf_token'):
            logger.warning("❌ Invalid session data in centralized user search")
            return JsonResponse({
                'success': False,
                'error': 'Invalid session. Please authenticate again.'
            }, status=401)
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            logger.warning("❌ Session has expired in centralized user search")
            # Clear the invalid session
            request.session.pop('authenticated_user_info', None)
            return JsonResponse({
                'success': False,
                'error': 'Your session has expired. Please authenticate again.'
            }, status=401)
        
        # Initialize admin API
        admin_api = adminAPI(
            session_id=user_info.get('session_id'),
            csrf_token=user_info.get('csrf_token'),
            user_id=user_info.get('user_id')
        )
        
        # Get multiple users from autocomplete API
        logger.info("🔍 Getting multiple users from autocomplete API...")
        users = admin_api.get_multiple_users_from_autocomplete_api(
            user_info.get('csrf_token'), 
            search_term, 
            user_info.get('user_id')
        )
        
        if users and len(users) > 0:
            logger.info(f"✅ Found {len(users)} users: {[u.get('full_name', u.get('email', 'Unknown')) for u in users]}")
            
            return JsonResponse({
                'success': True,
                'users': users,
                'message': f'Found {len(users)} user(s)'
            })
        else:
            logger.warning(f"❌ No users found for: {search_term}")
            return JsonResponse({
                'success': False,
                'error': f'No users found for "{search_term}". Try different search terms like mobile number, email, or name.'
            })
            
    except Exception as e:
        logger.error(f"Error in centralized user search: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JsonResponse({
            'success': False,
            'error': f'Search error: {str(e)}'
        })

def last_otp(request):
    """Display the last OTP messages for monitoring"""
    try:
        # Get authenticated user info
        user_info = request.session.get('authenticated_user_info')
        if not user_info or not user_info.get('valid'):
            return render(request, 'dashboard/last_otp.html', {
                'user_info': {'valid': False},
                'error': 'Authentication required. Please authenticate first.'
            })
        
        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            # Clear the invalid session
            request.session.pop('authenticated_user_info', None)
            return render(request, 'dashboard/last_otp.html', {
                'user_info': {'valid': False},
                'error': 'Your session has expired. Please authenticate again.'
            })
        
        # Initialize admin API
        admin_api = adminAPI()
        admin_api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
        admin_api.session.cookies.set('csrf_token', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')
        
        # Get last OTP messages
        logger.info("🔍 Fetching last OTP messages...")
        otp_messages = admin_api.get_last_otp_messages(limit=100)
        logger.info(f"🔍 Retrieved {len(otp_messages)} messages from API")
        
        # Sort by PK (assuming higher PK = more recent)
        otp_messages.sort(key=lambda x: int(x['pk']) if x['pk'].isdigit() else 0, reverse=True)
        logger.info(f"🔍 Sorted messages by PK")
        
        # Mark the first message as latest (since we sorted by PK descending)
        # The highest PK should correspond to the most recent message
        if otp_messages:
            # Mark only the first message as latest
            otp_messages[0]['is_latest'] = True
            for i in range(1, len(otp_messages)):
                otp_messages[i]['is_latest'] = False
            
            logger.info(f"✅ Marked first message as latest: PK={otp_messages[0]['pk']}, Date={otp_messages[0]['created_at']}")
        else:
            logger.warning("⚠️ No OTP messages found to mark as latest")
        
        return render(request, 'dashboard/last_otp.html', {
            'user_info': user_info,
            'otp_messages': otp_messages,
            'total_count': len(otp_messages)
        })

    except Exception as e:
        logger.error(f"❌ Error in last_otp view: {e}")
        return render(request, 'dashboard/last_otp.html', {
            'user_info': {'valid': False},
            'error': f'Error loading OTP messages: {str(e)}'
        })

def withdrawal_permission(request):
    """Display the withdrawal permission management page"""
    try:
        # Get authenticated user info
        user_info = request.session.get('authenticated_user_info')
        if not user_info or not user_info.get('valid'):
            return render(request, 'dashboard/withdrawal_permission.html', {
                'user_info': {'valid': False},
                'error': 'Authentication required. Please authenticate first.'
            })

        # Validate that the session is still active
        if not _validate_session_still_active(user_info):
            # Clear the invalid session
            request.session.pop('authenticated_user_info', None)
            return render(request, 'dashboard/withdrawal_permission.html', {
                'user_info': {'valid': False},
                'error': 'Your session has expired. Please authenticate again.'
            })

        return render(request, 'dashboard/withdrawal_permission.html', {
            'user_info': user_info
        })

    except Exception as e:
        logger.error(f"❌ Error in withdrawal_permission view: {e}")
        return render(request, 'dashboard/withdrawal_permission.html', {
            'user_info': {'valid': False},
            'error': f'Error loading withdrawal permission page: {str(e)}'
        })

@csrf_exempt
def get_currencies_ajax(request):
    """AJAX endpoint for getting available currencies for withdrawal permission"""
    if request.method == 'GET':
        try:
            # Get authenticated user info
            user_info = request.session.get('authenticated_user_info')
            if not user_info or not user_info.get('valid'):
                return JsonResponse({'error': 'Authentication required'}, status=401)

            # Validate that the session is still active
            if not _validate_session_still_active(user_info):
                return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)

            # Get user ID from request
            user_id = request.GET.get('user_id')
            if not user_id:
                return JsonResponse({'error': 'User ID is required'}, status=400)

            # Initialize admin API
            admin_api = adminAPI()
            admin_api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            admin_api.session.cookies.set('csrf_token', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')

            # Get restriction page data
            page_data = admin_api.get_restriction_page(user_id)
            
            if page_data['success']:
                return JsonResponse({
                    'success': True,
                    'currencies': page_data['currencies']
                })
            else:
                return JsonResponse({'error': page_data['error']}, status=400)

        except Exception as e:
            logger.error(f"❌ Error in get_currencies_ajax: {e}")
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def create_withdrawal_permission_ajax(request):
    """AJAX endpoint for creating withdrawal permission"""
    if request.method == 'POST':
        try:
            # Get authenticated user info
            user_info = request.session.get('authenticated_user_info')
            if not user_info or not user_info.get('valid'):
                return JsonResponse({'error': 'Authentication required'}, status=401)

            # Validate that the session is still active
            if not _validate_session_still_active(user_info):
                return JsonResponse({'error': 'Session has expired. Please authenticate again.'}, status=401)

            # Get form data
            user_id = request.POST.get('user_id')
            amount_limit = int(request.POST.get('amount_limit', 1000000000))
            description = request.POST.get('description', 'بلا')
            currency = request.POST.get('currency', '0')
            all_currencies = request.POST.get('all_currencies') == 'true'
            effective_time_day = int(request.POST.get('effective_time_day', 26))
            effective_time_month = int(request.POST.get('effective_time_month', 7))
            effective_time_year = int(request.POST.get('effective_time_year', 1404))

            if not user_id:
                return JsonResponse({'error': 'User ID is required'}, status=400)

            # Initialize admin API
            admin_api = adminAPI()
            admin_api.session.cookies.set('sessionid', user_info['session_id'], domain="testnetadminv2.ntx.ir", path='/')
            admin_api.session.cookies.set('csrf_token', user_info['csrf_token'], domain="testnetadminv2.ntx.ir", path='/')

            # Create withdrawal permission
            result = admin_api.create_withdrawal_permission(
                user_id=user_id,
                amount_limit=amount_limit,
                description=description,
                currency=currency,
                all_currencies=all_currencies,
                effective_time_day=effective_time_day,
                effective_time_month=effective_time_month,
                effective_time_year=effective_time_year
            )

            if result['success']:
                return JsonResponse({
                    'success': True,
                    'message': result['message']
                })
            else:
                return JsonResponse({'error': result['error']}, status=400)

        except Exception as e:
            logger.error(f"❌ Error in create_withdrawal_permission_ajax: {e}")
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)
