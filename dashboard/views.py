import logging
import json
import os
from django.shortcuts import render, redirect
from django.http import JsonResponse
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize logger
logger = logging.getLogger('dashboard')

# Neo4j driver setup with connection check
uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
user = os.getenv('NEO4J_USER', 'neo4j')
password = os.getenv('NEO4J_PASSWORD', 'password')

driver = None  # Global driver instance (will be reset per request in Django)

def get_driver():
    global driver
    if driver is None:
        try:
            driver = GraphDatabase.driver(uri, auth=(user, password))
            driver.verify_connectivity()  # Ensure the connection is valid
            logger.info("Established new Neo4j connection at %s", uri)
        except Exception as e:
            logger.error("Failed to establish Neo4j connection at %s: %s", uri, str(e))
            raise
    return driver

# Ensure the driver is closed after each request
def close_driver():
    global driver
    if driver is not None:
        driver.close()
        logger.info("Closed Neo4j connection at %s", uri)
        driver = None

# Helper functions for PredefinedQuery in Neo4j
def create_predefined_query(query_name, query_text):
    """Create a new predefined query in Neo4j."""
    with get_driver().session() as session:
        session.run(
            "CREATE (q:PredefinedQuery {id: randomUUID(), name: $name, query: $query})",
            {"name": query_name, "query": query_text}
        )

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
        if record:
            return {'id': record["q.id"], 'name': record["q.name"], 'query': record["q.query"]}
        return None

def delete_predefined_query_by_id(query_id):
    """Delete a predefined query by ID from Neo4j."""
    with get_driver().session() as session:
        session.run(
            "MATCH (q:PredefinedQuery {id: $id}) DETACH DELETE q",
            {"id": query_id}
        )

def get_existing_nodes():
    """Retrieve all existing node names from the database."""
    logger.debug("Entering get_existing_nodes")
    try:
        with get_driver().session() as session:
            logger.debug("Checking Neo4j connection before query")
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            nodes = [record["name"] for record in result]
            logger.debug("Retrieved existing nodes: %s", nodes)
            return nodes
    except Exception as e:
        logger.error("Error retrieving existing nodes: %s", str(e))
        return []

def home(request):
    """Render the home page with predefined queries."""
    logger.debug("Entering home view")
    
    # دریافت پرس‌وجوهای از پیش تعریف‌شده از Neo4j
    predefined_queries = []
    try:
        with get_driver().session() as session:
            result = session.run("MATCH (q:PredefinedQuery) RETURN q.id, q.name, q.query")
            predefined_queries = [
                {'id': record['q.id'], 'name': record['q.name'], 'query': record['q.query']}
                for record in result
            ]
        logger.debug("Retrieved predefined queries: %s", predefined_queries)
    except Exception as e:
        logger.error("Error retrieving predefined queries: %s", str(e))

    logger.debug("Rendering home.html")
    return render(request, 'dashboard/home.html', {
        'predefined_queries': predefined_queries
    })

def add_nodes(request):
    """Add new nodes to the database."""
    logger.debug("Entering add_nodes view with request method: %s", request.method)
    error = None  
    if request.method == 'POST':
        nodes_input = request.POST.get('nodes', '').strip()
        logger.debug("Received nodes input: %s", nodes_input)
        if not nodes_input:
            error = 'Please enter at least one node.'
            logger.warning("Validation failed: No nodes provided")
        else:
            nodes = [node.strip() for node in nodes_input.split('\n') if node.strip()]
            logger.debug("Processed nodes: %s", nodes)
            if not nodes:
                error = 'No valid nodes provided.'
                logger.warning("Validation failed: No valid nodes after processing")
            else:
                request.session['nodes'] = nodes
                logger.debug("Stored nodes in session: %s", nodes)
                return redirect('relationship_option')

    logger.debug("Rendering add_nodes.html with error: %s", error)
    return render(request, 'dashboard/add_nodes.html', {'error': error})

def relationship_option(request):
    """Ask if the new nodes have relationships with existing nodes."""
    logger.debug("Entering relationship_option view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    logger.debug("Retrieved nodes from session: %s", nodes)
    
    error = None

    if not nodes:
        error = 'No nodes found in session. Please start over.'
        logger.warning("No nodes found in session")
        return render(request, 'dashboard/relationship_option.html', {
            'error': error
        })

    if request.method == 'POST':
        add_relationships = request.POST.get('add_relationships')
        logger.debug("Received add_relationships: %s", add_relationships)
        if not add_relationships:
            error = 'Please select an option.'
            logger.warning("Validation failed: No option selected")
        else:
            if add_relationships == 'yes':
                logger.debug("User chose to add relationships with existing nodes")
                return redirect('input_existing_nodes')
            else:
                logger.debug("User chose not to add relationships with existing nodes")
                return redirect('define_new_node_relations')

    logger.debug("Rendering relationship_option.html")
    return render(request, 'dashboard/relationship_option.html', {
        'error': error
    })

def input_existing_nodes(request):
    """Input existing nodes to relate with new nodes."""
    logger.debug("Entering input_existing_nodes view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    existing_nodes_list = get_existing_nodes()
    logger.debug("Retrieved session data - nodes: %s, existing_nodes_list: %s", nodes, existing_nodes_list)
    
    error = None

    if not nodes:
        error = 'No new nodes found in session. Please start over.'
        logger.warning("No new nodes found in session")
        return render(request, 'dashboard/input_existing_nodes.html', {
            'error': error,
            'nodes': nodes,
            'existing_nodes_list': existing_nodes_list
        })

    if request.method == 'POST':
        existing_nodes = request.POST.getlist('existing_nodes')
        logger.debug("Received existing nodes: %s", existing_nodes)
        if not existing_nodes:
            error = 'Please select at least one existing node.'
            logger.warning("Validation failed: No existing nodes selected")
        else:
            request.session['existing_nodes'] = existing_nodes
            logger.debug("Stored existing nodes in session: %s", existing_nodes)
            return redirect('define_relations_with_existing_nodes')

    logger.debug("Rendering input_existing_nodes.html")
    return render(request, 'dashboard/input_existing_nodes.html', {
        'nodes': nodes,
        'existing_nodes_list': existing_nodes_list,
        'error': error
    })

def define_new_node_relations(request):
    """Define relationships between new nodes."""
    logger.debug("Entering define_new_node_relations view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    logger.debug("Retrieved nodes from session: %s", nodes)
    
    error = None

    if not nodes:
        error = 'No nodes found in session. Please start over.'
        logger.warning("No nodes found in session")
        return render(request, 'dashboard/define_new_node_relations.html', {
            'error': error,
            'nodes': nodes
        })

    if request.method == 'POST':
        relationships = request.POST.getlist('relationships')
        logger.debug("Received relationships: %s", relationships)
        if not relationships:
            error = 'Please select at least one relationship.'
            logger.warning("Validation failed: No relationships selected")
        else:
            relationships = [tuple(rel.split(',')) for rel in relationships]
            logger.debug("Processed relationships: %s", relationships)
            request.session['relationships'] = relationships
            logger.debug("Stored relationships in session: %s", relationships)
            return redirect('confirm_relations')

    logger.debug("Rendering define_new_node_relations.html")
    return render(request, 'dashboard/define_new_node_relations.html', {
        'nodes': nodes,
        'error': error
    })

def confirm_relations(request):
    """Display and confirm the Cypher query before execution."""
    logger.debug("Entering confirm_relations view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    relationships = request.session.get('relationships', [])
    logger.debug("Retrieved session data - nodes: %s, existing_nodes: %s, relationships: %s", nodes, existing_nodes, relationships)
    
    error = None
    success = None

    if not nodes or not relationships:
        error = 'Session data missing. Please start over.'
        logger.warning("Session data missing: nodes or relationships not found")
        return render(request, 'dashboard/confirm_relations.html', {
            'error': error,
            'nodes': nodes,
            'existing_nodes': existing_nodes,
            'relationships': relationships,
            'cypher_query': ''  # در صورت خطا، مقدار پیش‌فرض خالی
        })

    # ساخت Cypher query برای نمایش به کاربر
    cypher_query = "CREATE "
    new_nodes_to_create = [node for node in nodes if node not in get_existing_nodes()]
    if new_nodes_to_create:
        cypher_query += ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in new_nodes_to_create])
        if existing_nodes:
            cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in new_nodes_to_create])
    if existing_nodes:
        if new_nodes_to_create:
            cypher_query += ", "
        cypher_query += "\nMATCH " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in existing_nodes])
    if relationships:
        relationship_clauses = "\nCREATE " + ", CREATE ".join(
            [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships
             if rel[0] in nodes + existing_nodes and rel[1] in nodes + existing_nodes]
        )
        cypher_query += relationship_clauses

    if request.method == 'POST':
        action = request.POST.get('action')
        logger.debug("Received action: %s", action)
        if action == 'confirm':
            logger.debug("Checking Neo4j connection before query")
            try:
                with get_driver().session() as session:
                    session.run(cypher_query)
                success = 'Nodes and relationships created successfully.'
                logger.info("Nodes and relationships created successfully")
                # پاک کردن داده‌های session بعد از موفقیت
                request.session.pop('nodes', None)
                request.session.pop('existing_nodes', None)
                request.session.pop('relationships', None)
                logger.debug("Cleared session data")
                return redirect('home')
            except Exception as e:
                error = f'Error creating nodes and relationships: {str(e)}'
                logger.error("Error creating nodes and relationships: %s", str(e))
        else:
            success = 'Operation cancelled.'
            logger.info("Operation cancelled by user")
            # پاک کردن داده‌های session در صورت لغو
            request.session.pop('nodes', None)
            request.session.pop('existing_nodes', None)
            request.session.pop('relationships', None)
            logger.debug("Cleared session data")
            return redirect('home')

    logger.debug("Rendering confirm_relations.html with cypher_query: %s", cypher_query)
    return render(request, 'dashboard/confirm_relations.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'relationships': relationships,
        'cypher_query': cypher_query,
        'error': error,
        'success': success
    })

def manual_query(request):
    """Execute a manual Cypher query and display the result as a graph."""
    logger.debug("Entering manual_query view with request method: %s", request.method)
    result = None
    error = None
    if request.method == 'POST':
        query = request.POST.get('query', '').strip()
        logger.debug("Received manual query: %s", query)
        if not query:
            error = 'Please enter a Cypher query.'
            logger.warning("Validation failed: No query provided")
        else:
            logger.debug("Checking Neo4j connection before query")
            try:
                with get_driver().session() as session:
                    result = session.run(query)
                    nodes = []
                    edges = []
                    seen_nodes = set()  # To avoid duplicate nodes
                    for record in result:
                        logger.debug("Processing record: %s", list(record.values()))
                        for item in record.values():
                            # Handle nodes
                            if isinstance(item, dict):
                                node_prop = item.get('name') or item.get('title') or item.get('id')
                                if node_prop:
                                    node_id = str(node_prop).replace(' ', '_')
                                    if node_id not in seen_nodes:
                                        nodes.append({'id': node_id, 'label': node_prop, 'x': None, 'y': None})
                                        seen_nodes.add(node_id)
                                        logger.debug("Added node: %s", node_id)
                            # Handle relationships
                            elif hasattr(item, 'start_node') and hasattr(item, 'end_node'):
                                source_prop = item.start_node.get('name') or item.start_node.get('title') or item.start_node.get('id')
                                target_prop = item.end_node.get('name') or item.end_node.get('title') or item.end_node.get('id')
                                if source_prop and target_prop:
                                    source_id = str(source_prop).replace(' ', '_')
                                    target_id = str(target_prop).replace(' ', '_')
                                    # Ensure nodes are added even if not explicitly returned
                                    if source_id not in seen_nodes:
                                        nodes.append({'id': source_id, 'label': source_prop, 'x': None, 'y': None})
                                        seen_nodes.add(source_id)
                                        logger.debug("Added source node: %s", source_id)
                                    if target_id not in seen_nodes:
                                        nodes.append({'id': target_id, 'label': target_prop, 'x': None, 'y': None})
                                        seen_nodes.add(target_id)
                                        logger.debug("Added target node: %s", target_id)
                                    edge_id = f"{source_id}_{target_id}"
                                    edges.append({'id': edge_id, 'source': source_id, 'target': target_id, 'label': 'R'})
                                    logger.debug("Added edge: %s -> %s", source_id, target_id)
                    result = {'nodes': nodes, 'edges': edges}
                    logger.debug("Manual query result - Nodes: %d, Edges: %d", len(nodes), len(edges))
                    logger.debug("Result JSON: %s", json.dumps(result, indent=2))
            except Exception as e:
                error = f'Query error: {str(e)}'
                logger.error("Manual query execution failed: %s", str(e))

    logger.debug("Rendering manual_query.html with error: %s, result: %s", error, result is not None)
    return render(request, 'dashboard/manual_query.html', {
        'result_json': json.dumps(result) if result else None,
        'error': error,
    })

def admin_queries(request):
    """Manage predefined queries."""
    logger.debug("Entering admin_queries view with request method: %s", request.method)
    error = None
    success = None

    # Check for messages stored in session (from delete_predefined_query)
    if 'success' in request.session:
        success = request.session.pop('success')
    if 'error' in request.session:
        error = request.session.pop('error')

    if request.method == 'POST':
        query_name = request.POST.get('query_name', '').strip()
        query_text = request.POST.get('query_text', '').strip()
        logger.debug("Received POST data - query_name: %s, query_text: %s", query_name, query_text)
        if not query_name or not query_text:
            error = 'Please provide both a query name and the query text.'
            logger.warning("Validation failed: Query name or text missing")
        else:
            try:
                create_predefined_query(query_name, query_text)
                success = 'Predefined query added successfully.'
                logger.info("Predefined query added: %s", query_name)
            except Exception as e:
                error = f'Error adding query: {str(e)}'
                logger.error("Error adding predefined query: %s", str(e))

    predefined_queries = get_all_predefined_queries()
    logger.debug("Rendering admin_queries.html with predefined_queries: %s", predefined_queries)
    return render(request, 'dashboard/admin_queries.html', {
        'predefined_queries': predefined_queries,
        'error': error,
        'success': success
    })

def delete_predefined_query(request, query_id):
    """Delete a predefined query."""
    logger.debug("Entering delete_predefined_query view with query_id: %s", query_id)
    try:
        delete_predefined_query_by_id(query_id)
        request.session['success'] = 'Predefined query deleted successfully.'
        logger.info("Predefined query deleted: %s", query_id)
    except Exception as e:
        request.session['error'] = f'Error deleting query: {str(e)}'
        logger.error("Error deleting predefined query: %s", str(e))
    return redirect('admin_queries')

def predefined_query_result(request, query_id):
    """Execute a predefined query and display the result."""
    logger.debug("Entering predefined_query_result view with query_id: %s", query_id)
    error = None
    result = None
    query_obj = None

    try:
        query_obj = get_predefined_query_by_id(query_id)
        if not query_obj:
            error = 'Query not found.'
            logger.warning("Query not found: %s", query_id)
            return render(request, 'dashboard/predefined_query_result.html', {
                'error': error,
                'query': query_obj,
                'result_json': None
            })

        logger.debug("Retrieved predefined query: %s", query_obj['query'])
        logger.debug("Checking Neo4j connection before query")
        with get_driver().session() as session:
            result = session.run(query_obj['query'])
            nodes = []
            edges = []
            seen_nodes = set()  # To avoid duplicates
            for record in result:
                for item in record.values():
                    if isinstance(item, dict):
                        node_prop = item.get('name') or item.get('title') or item.get('id')
                        if node_prop:
                            node_id = str(node_prop).replace(' ', '_')
                            if node_id not in seen_nodes:
                                nodes.append({'id': node_id, 'label': node_prop, 'x': None, 'y': None})
                                seen_nodes.add(node_id)
                    elif hasattr(item, 'start_node') and hasattr(item, 'end_node'):
                        source_prop = item.start_node.get('name') or item.start_node.get('title') or item.start_node.get('id')
                        target_prop = item.end_node.get('name') or item.end_node.get('title') or item.end_node.get('id')
                        if source_prop and target_prop:
                            source_id = str(source_prop).replace(' ', '_')
                            target_id = str(target_prop).replace(' ', '_')
                            if source_id not in seen_nodes:
                                nodes.append({'id': source_id, 'label': source_prop, 'x': None, 'y': None})
                                seen_nodes.add(source_id)
                            if target_id not in seen_nodes:
                                nodes.append({'id': target_id, 'label': target_prop, 'x': None, 'y': None})
                                seen_nodes.add(target_id)
                            edges.append({'id': f"{source_id}_{target_id}", 'source': source_id, 'target': target_id, 'label': 'R'})
            result = {'nodes': nodes, 'edges': edges}
            logger.debug("Predefined query result: %s", json.dumps(result, indent=2))
    except Exception as e:
        error = f'Query error: {str(e)}'
        logger.error("Predefined query execution failed: %s", str(e))

    logger.debug("Rendering predefined_query_result.html with result")
    return render(request, 'dashboard/predefined_query_result.html', {
        'query': query_obj,
        'result_json': json.dumps(result) if result else None,
        'error': error
    })

def check_node_duplicate(request):
    """Check if a node name already exists."""
    logger.debug("Entering check_node_duplicate view with request method: %s", request.method)
    node_name = request.GET.get('node_name', '').strip()
    logger.debug("Checking for duplicate node: %s", node_name)
    existing_nodes = get_existing_nodes()
    exists = node_name in existing_nodes
    logger.debug("Node exists: %s", exists)
    return JsonResponse({'exists': exists})

def select_relationships(request):
    """Select existing nodes to create relationships with new nodes."""
    logger.debug("Entering select_relationships view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    existing_nodes = get_existing_nodes()
    logger.debug("Retrieved session data - nodes: %s, existing_nodes: %s", nodes, existing_nodes)
    
    error = None

    if not nodes:
        error = 'No new nodes found in session. Please start over.'
        logger.warning("No new nodes found in session")
        return render(request, 'dashboard/select_relationships.html', {
            'error': error,
            'nodes': nodes,
            'existing_nodes': existing_nodes
        })

    if request.method == 'POST':
        selected_existing_nodes = request.POST.getlist('existing_nodes')
        logger.debug("Received selected existing nodes: %s", selected_existing_nodes)
        if not selected_existing_nodes:
            error = 'Please select at least one existing node.'
            logger.warning("Validation failed: No existing nodes selected")
        else:
            request.session['existing_nodes'] = selected_existing_nodes
            logger.debug("Stored selected existing nodes in session: %s", selected_existing_nodes)
            return redirect('confirm_relationships')

    logger.debug("Rendering select_relationships.html")
    return render(request, 'dashboard/select_relationships.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'error': error
    })

def confirm_relationships(request):
    """Confirm relationships before saving."""
    logger.debug("Entering confirm_relationships view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    relationships = request.session.get('relationships', [])
    logger.debug("Retrieved session data - nodes: %s, relationships: %s", nodes, relationships)
    
    error = None
    success = None

    if not nodes or not relationships:
        error = 'Session data missing. Please start over.'
        logger.warning("Session data missing: nodes or relationships not found")
        return render(request, 'dashboard/confirm_relationships.html', {
            'error': error,
            'nodes': nodes,
            'relationships': relationships,
            'cypher_query': ''  # در صورت خطا، مقدار پیش‌فرض خالی
        })

    # ساخت Cypher query برای نمایش به کاربر
    cypher_query = "CREATE "
    cypher_query += ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in nodes])
    cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in nodes])
    cypher_query += "\nCREATE " + ", CREATE ".join(
        [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships]
    )

    if request.method == 'POST':
        action = request.POST.get('action')
        logger.debug("Received action: %s", action)
        if action == 'confirm':
            logger.debug("Checking Neo4j connection before query")
            try:
                with get_driver().session() as session:
                    session.run(cypher_query)
                success = 'Relationships created successfully.'
                logger.info("Relationships created successfully")
                # پاک کردن داده‌های session بعد از موفقیت
                request.session.pop('nodes', None)
                request.session.pop('relationships', None)
                logger.debug("Cleared session data")
                return redirect('home')
            except Exception as e:
                error = f'Error creating relationships: {str(e)}'
                logger.error("Error creating relationships: %s", str(e))
        else:
            success = 'Operation cancelled.'
            logger.info("Operation cancelled by user")
            # پاک کردن داده‌های session در صورت لغو
            request.session.pop('nodes', None)
            request.session.pop('relationships', None)
            logger.debug("Cleared session data")
            return redirect('home')

    logger.debug("Rendering confirm_relationships.html")
    return render(request, 'dashboard/confirm_relationships.html', {
        'nodes': nodes,
        'relationships': relationships,
        'cypher_query': cypher_query,
        'error': error,
        'success': success
    })

def explore_layers(request):
    """Handle exploration of nodes up to a specified number of layers."""
    logger.debug("Entering explore_layers view with request method: %s", request.method)
    error = None
    result = None
    if request.method == 'POST':
        node_name = request.POST.get('node_name', '').strip()
        depth = request.POST.get('depth')
        logger.debug("Received POST data - node_name: %s, depth: %s", node_name, depth)

        if not node_name or not depth:
            error = 'Please enter both a node name and depth.'
            logger.warning("Validation failed: node_name or depth is missing")
        else:
            try:
                depth = int(depth)
                logger.debug("Converted depth to integer: %d", depth)
                if depth < 0:
                    error = 'Depth must be a non-negative integer.'
                    logger.warning("Validation failed: Depth is negative (%d)", depth)
                else:
                    with get_driver().session() as session:
                        logger.debug("Checking Neo4j connection before query")
                        query = """
                            MATCH (start:Node)
                            WHERE start.name = $node_name
                            MATCH (start)-[*1..$depth]->(end:Node)
                            WHERE end <> start
                            RETURN DISTINCT end.name AS connected_node_names
                        """
                        logger.debug("Constructed Cypher query: %s", query)
                        logger.debug("Parameters - node_name: %s, depth: %d", node_name, depth)

                        result = session.run(query, {"node_name": node_name, "depth": depth})
                        logger.debug("Query executed successfully")

                        nodes = {}
                        edges = []
                        for record in result:
                            connected_node = record["connected_node_names"]
                            logger.debug("Processing connected node: %s", connected_node)
                            if node_name not in nodes:
                                nodes[node_name] = {'id': node_name.replace(' ', '_'), 'label': node_name}
                            if connected_node not in nodes:
                                nodes[connected_node] = {'id': connected_node.replace(' ', '_'), 'label': connected_node}
                            edges.append({
                                'id': f"{node_name}_{connected_node}",
                                'source': node_name.replace(' ', '_'),
                                'target': connected_node.replace(' ', '_'),
                                'label': 'R'
                            })

                        result = {
                            'nodes': [{'id': data['id'], 'label': data['label'], 'x': None, 'y': None} for data in nodes.values()],
                            'edges': edges
                        }
                        logger.debug("Result JSON: %s", json.dumps(result, indent=2))

            except ValueError as ve:
                error = 'Depth must be a valid integer.'
                logger.error("ValueError in depth conversion: %s", str(ve))
            except Exception as e:
                error = f'Query error: {str(e)}'
                logger.error("Query execution failed: %s", str(e))

    logger.debug("Rendering explore_layers.html with error: %s, result: %s", error, result is not None)
    return render(request, 'dashboard/explore_layers.html', {
        'error': error,
        'result_json': json.dumps(result) if result else None
    })

def define_relations_with_existing_nodes(request):
    """Define relationships between new nodes and existing nodes."""
    logger.debug("Entering define_relations_with_existing_nodes view with request method: %s", request.method)
    new_nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    logger.debug("Retrieved session data - new_nodes: %s, existing_nodes: %s", new_nodes, existing_nodes)
    
    error = None

    if not new_nodes or not existing_nodes:
        error = 'Session data missing. Please start over.'
        logger.warning("Session data missing: new_nodes or existing_nodes not found")
        return render(request, 'dashboard/define_relations_with_existing_nodes.html', {
            'error': error,
            'new_nodes': new_nodes,
            'existing_nodes': existing_nodes
        })

    if request.method == 'POST':
        relations = request.POST.getlist('relations')
        logger.debug("Received relations: %s", relations)
        if not relations:
            error = 'Please select at least one relationship.'
            logger.warning("Validation failed: No relations selected")
        else:
            relationships = [tuple(rel.split(',')) for rel in relations]
            logger.debug("Processed relationships: %s", relationships)
            # اضافه کردن روابط به session
            existing_relationships = request.session.get('relationships', [])
            request.session['relationships'] = existing_relationships + relationships
            logger.debug("Updated relationships in session: %s", request.session['relationships'])
            return redirect('define_new_node_relations')

    logger.debug("Rendering define_relations_with_existing_nodes.html")
    return render(request, 'dashboard/define_relations_with_existing_nodes.html', {
        'new_nodes': new_nodes,
        'existing_nodes': existing_nodes,
        'error': error
    })