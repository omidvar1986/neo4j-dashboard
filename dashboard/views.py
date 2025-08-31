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
from .forms import CustomUserCreationForm
from .models import user
import uuid
import csv
from .models import TestResult, ComponentDependency, TestCoverage
from django.db.models import Avg, Count
import requests
from datetime import datetime
import time
from collections import deque, defaultdict

# Load environment variables from .env file
load_dotenv()

# Initialize logger
logger = logging.getLogger('dashboard')

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
    query_executed = True

    if request.method == 'POST':
        action = request.POST.get('action')
        cypher_query = request.POST.get('cypher_query', '').strip()

        if action == 'clear':
            logger.info("User cleared the query and graph")
            return redirect('dashboard:manual_queries')

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
                })

            # Check if query is safe
            if not is_safe_query(cypher_query):
                logger.warning("Unsafe Cypher query detected: %s", cypher_query)
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': 'Unsafe query detected. Only MATCH and RETURN queries are allowed.',
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                    'query_executed': query_executed,
                })

            try:
                driver = get_driver()
                with driver.session() as session:
                    # Execute the query and collect nodes and relationships
                    result = session.run(cypher_query)
                    node_id_map = {}
                    node_counter = 0
                    found_nodes = False

                    for record in result:
                        for value in record.values():
                            # Process nodes
                            if isinstance(value, Node):
                                found_nodes = True
                                node_id = value.get('name', f"Node_{node_counter}")
                                node_counter += 1
                                node_id_map[id(value)] = node_id
                                if not any(node['id'] == node_id for node in graph_data['nodes']):
                                    logger.debug("Adding node: %s", node_id)
                                    labels = list(value.labels)
                                    properties = dict(value)
                                    graph_data['nodes'].append({
                                        'id': node_id,
                                        'label': node_id,
                                        'labels': labels,
                                        'properties': properties,
                                    })
                            # Process relationships
                            elif isinstance(value, Relationship):
                                source_id = node_id_map.get(id(value.start_node))
                                target_id = node_id_map.get(id(value.end_node))
                                if source_id and target_id:
                                    edge_id = f"edge-{len(graph_data['edges'])}"
                                    if not any(e['id'] == edge_id for e in graph_data['edges']):
                                        logger.debug("Adding edge: %s -> %s", source_id, target_id)
                                        graph_data['edges'].append({
                                            'id': edge_id,
                                            'source': source_id,
                                            'target': target_id,
                                            'label': value.type,
                                        })
                            # Process paths
                            elif isinstance(value, Path):
                                found_nodes = True
                                for node in value.nodes:
                                    node_id = node.get('name', f"Node_{node_counter}")
                                    node_counter += 1
                                    node_id_map[id(node)] = node_id
                                    if not any(node['id'] == node_id for node in graph_data['nodes']):
                                        logger.debug("Adding node from path: %s", node_id)
                                        labels = list(node.labels)
                                        properties = dict(node)
                                        graph_data['nodes'].append({
                                            'id': node_id,
                                            'label': node_id,
                                            'labels': labels,
                                            'properties': properties,
                                        })
                                for rel in value.relationships:
                                    source_id = node_id_map.get(id(rel.start_node))
                                    target_id = node_id_map.get(id(rel.end_node))
                                    if source_id and target_id:
                                        edge_id = f"edge-{len(graph_data['edges'])}"
                                        if not any(e['id'] == edge_id for e in graph_data['edges']):
                                            logger.debug("Adding edge from path: %s -> %s", source_id, target_id)
                                            graph_data['edges'].append({
                                                'id': edge_id,
                                                'source': source_id,
                                                'target': target_id,
                                                'label': rel.type,
                                            })

                    # If no nodes were found
                    if not found_nodes:
                        logger.warning("No nodes found with query: %s", cypher_query)
                        return render(request, 'dashboard/manual_queries.html', {
                            'error_message': 'No nodes found. Check your query or database.',
                            'graph_data': graph_data,
                            'cypher_query': cypher_query,
                            'nodes_json': json.dumps([]),
                            'edges_json': json.dumps([]),
                            'query_executed': query_executed,
                        })

                    logger.debug("Final graph data: %s", graph_data)
                    logger.info("Successfully executed Cypher query: %s", cypher_query)

                    # If we have nodes but no edges, we still want to show the nodes
                    if graph_data['nodes'] and not graph_data['edges']:
                        nodes_json = json.dumps(graph_data['nodes'])
                        edges_json = json.dumps([])
                    else:
                        nodes_json = json.dumps(graph_data['nodes'])
                        edges_json = json.dumps(graph_data['edges'])

                    logger.debug("nodes_json: %s", nodes_json)
                    logger.debug("edges_json: %s", edges_json)

                    return render(request, 'dashboard/manual_queries.html', {
                        'success_message': 'Query executed successfully.',
                        'nodes_json': nodes_json,
                        'edges_json': edges_json,
                        'cypher_query': cypher_query,
                        'query_executed': query_executed,
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
                })

    return render(request, 'dashboard/manual_queries.html', {
        'graph_data': graph_data,
        'cypher_query': cypher_query,
        'nodes_json': json.dumps([]),
        'edges_json': json.dumps([]),
        'query_executed': query_executed,
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