import logging
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from neo4j import GraphDatabase
from .models import PredefinedQuery
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm

# Initialize logger
logger = logging.getLogger('dashboard')

# Neo4j driver setup
driver = GraphDatabase.driver("bolt://neo4j:7687", auth=("neo4j", "password"))

def get_existing_nodes():
    """Retrieve all existing node names from the database."""
    logger.debug("Entering get_existing_nodes")
    try:
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            nodes = [record["name"] for record in result]
            logger.debug("Retrieved existing nodes: %s", nodes)
            return nodes
    except Exception as e:
        logger.error("Error retrieving existing nodes: %s", str(e))
        return []

def home(request):
    """Display the home page with navigation options."""
    logger.debug("Entering home view with request method: %s", request.method)
    options = [
        {'name': 'Add Nodes', 'url': 'add_nodes'},
        {'name': 'Manual Query', 'url': 'manual_query'},
        {'name': 'Admin Queries', 'url': 'admin_queries'},
        {'name': 'Explore Node Layers', 'url': 'explore_layers'},
    ]
    predefined_queries = PredefinedQuery.objects.all() if request.user.is_authenticated else None
    logger.debug("Rendering home.html with options: %s, predefined_queries: %s", options, predefined_queries)
    return render(request, 'dashboard/home.html', {
        'options': options,
        'predefined_queries': predefined_queries,
    })

def add_nodes(request):
    """Add new nodes to the database."""
    logger.debug("Entering add_nodes view with request method: %s", request.method)
    if request.method == 'POST':
        nodes_input = request.POST.get('nodes', '').strip()
        logger.debug("Received nodes input: %s", nodes_input)
        if not nodes_input:
            messages.error(request, 'Please enter at least one node.')
            logger.warning("Validation failed: No nodes provided")
            return redirect('add_nodes')

        nodes = [node.strip() for node in nodes_input.split('\n') if node.strip()]
        logger.debug("Processed nodes: %s", nodes)
        if not nodes:
            messages.error(request, 'No valid nodes provided.')
            logger.warning("Validation failed: No valid nodes after processing")
            return redirect('add_nodes')

        request.session['nodes'] = nodes
        logger.debug("Stored nodes in session: %s", nodes)
        return redirect('relationship_option')

    logger.debug("Rendering add_nodes.html")
    return render(request, 'dashboard/add_nodes.html')

def relationship_option(request):
    """Ask if the user wants to add relationships between nodes."""
    logger.debug("Entering relationship_option view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    logger.debug("Retrieved nodes from session: %s", nodes)
    if not nodes:
        messages.error(request, 'No nodes found. Please start over.')
        logger.warning("Session data missing: No nodes found")
        return redirect('add_nodes')

    if request.method == 'POST':
        add_relationships = request.POST.get('add_relationships')
        logger.debug("Received add_relationships choice: %s", add_relationships)
        if add_relationships == 'yes':
            return redirect('input_existing_nodes')
        else:
            existing_nodes = get_existing_nodes()
            logger.debug("No relationships to add, proceeding with existing nodes: %s", existing_nodes)
            request.session['existing_nodes'] = existing_nodes
            request.session['relationships'] = []
            return redirect('confirm_relations')

    logger.debug("Rendering relationship_option.html with nodes: %s", nodes)
    return render(request, 'dashboard/relationship_option.html', {'nodes': nodes})

def input_existing_nodes(request):
    """Allow user to input existing nodes for relationships."""
    logger.debug("Entering input_existing_nodes view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    logger.debug("Retrieved nodes from session: %s", nodes)
    if not nodes:
        messages.error(request, 'No nodes found. Please start over.')
        logger.warning("Session data missing: No nodes found")
        return redirect('add_nodes')

    existing_nodes = get_existing_nodes()
    logger.debug("Retrieved existing nodes: %s", existing_nodes)
    if request.method == 'POST':
        selected_nodes = request.POST.getlist('existing_nodes')
        logger.debug("Received selected existing nodes: %s", selected_nodes)
        if not selected_nodes:
            messages.error(request, 'Please select at least one existing node.')
            logger.warning("Validation failed: No existing nodes selected")
            return redirect('input_existing_nodes')

        request.session['existing_nodes'] = selected_nodes
        logger.debug("Stored existing nodes in session: %s", selected_nodes)
        return redirect('define_new_node_relations')

    logger.debug("Rendering input_existing_nodes.html with nodes: %s, existing_nodes: %s", nodes, existing_nodes)
    return render(request, 'dashboard/input_existing_nodes.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
    })

def define_new_node_relations(request):
    """Define relationships between new and existing nodes."""
    logger.debug("Entering define_new_node_relations view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    logger.debug("Retrieved session data - nodes: %s, existing_nodes: %s", nodes, existing_nodes)
    if not nodes or not existing_nodes:
        messages.error(request, 'Session data missing. Please start over.')
        logger.warning("Session data missing: nodes or existing_nodes not found")
        return redirect('add_nodes')

    all_nodes = nodes + existing_nodes
    logger.debug("Combined all nodes: %s", all_nodes)
    if request.method == 'POST':
        relationships = []
        for node1 in all_nodes:
            for node2 in all_nodes:
                if node1 != node2:
                    relationship_key = f'relationship_{node1}_{node2}'
                    if request.POST.get(relationship_key) == 'on':
                        relationships.append((node1, node2))
        logger.debug("Defined relationships: %s", relationships)
        request.session['relationships'] = relationships
        return redirect('confirm_relations')

    logger.debug("Rendering define_new_node_relations.html with nodes: %s, existing_nodes: %s", nodes, existing_nodes)
    return render(request, 'dashboard/define_new_node_relations.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'all_nodes': all_nodes,
    })

def confirm_relations(request):
    """Display and confirm the Cypher query before execution."""
    logger.debug("Entering confirm_relations view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    relationships = request.session.get('relationships', [])
    logger.debug("Retrieved session data - nodes: %s, existing_nodes: %s, relationships: %s", nodes, existing_nodes, relationships)
    if not nodes or not existing_nodes:
        messages.error(request, 'Session data missing. Please start over.')
        logger.warning("Session data missing: nodes or existing_nodes not found")
        return redirect('add_nodes')

    if request.method == 'POST':
        action = request.POST.get('action')
        logger.debug("Received action: %s", action)
        if action == 'confirm':
            cypher_query = ""
            new_nodes_to_create = [node for node in nodes if node not in get_existing_nodes()]
            logger.debug("New nodes to create: %s", new_nodes_to_create)
            if new_nodes_to_create:
                cypher_query += "CREATE " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in new_nodes_to_create])
                cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in new_nodes_to_create])
            if existing_nodes:
                cypher_query += "\nMATCH " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in existing_nodes])
            if relationships:
                relationship_clauses = "\nCREATE " + ", CREATE ".join(
                    [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships
                     if rel[0] in nodes + existing_nodes and rel[1] in nodes + existing_nodes]
                )
                cypher_query += relationship_clauses

            logger.debug("Constructed Cypher query for execution: %s", cypher_query)
            try:
                with driver.session() as session:
                    session.run(cypher_query)
                messages.success(request, 'Nodes and relationships created successfully.')
                logger.info("Nodes and relationships created successfully")
            except Exception as e:
                messages.error(request, f'Error creating nodes and relationships: {str(e)}')
                logger.error("Error creating nodes and relationships: %s", str(e))
            finally:
                request.session.pop('nodes', None)
                request.session.pop('existing_nodes', None)
                request.session.pop('relationships', None)
                logger.debug("Cleared session data")
            return redirect('home')
        else:
            messages.info(request, 'Operation cancelled.')
            logger.info("Operation cancelled by user")
            return redirect('home')

    cypher_query = "CREATE "
    new_nodes_to_create = [node for node in nodes if node not in get_existing_nodes()]
    if new_nodes_to_create:
        cypher_query += ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in new_nodes_to_create])
        cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in new_nodes_to_create])
    if existing_nodes:
        cypher_query += "\nMATCH " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in existing_nodes])
    if relationships:
        relationship_clauses = "\nCREATE " + ", CREATE ".join(
            [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships
             if rel[0] in nodes + existing_nodes and rel[1] in nodes + existing_nodes]
        )
        cypher_query += relationship_clauses

    logger.debug("Rendering confirm_relations.html with cypher_query: %s", cypher_query)
    return render(request, 'dashboard/confirm_relations.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'relationships': relationships,
        'cypher_query': cypher_query
    })

def manual_query(request):
    """Execute a manual Cypher query."""
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
            try:
                with driver.session() as session:
                    result = session.run(query)
                    nodes = []
                    edges = []
                    for record in result:
                        for item in record.values():
                            if isinstance(item, dict):
                                if 'name' in item:
                                    node_id = item['name'].replace(' ', '_')
                                    nodes.append({'id': node_id, 'label': item['name']})
                            elif hasattr(item, 'start_node') and hasattr(item, 'end_node'):
                                source = item.start_node.get('name', '').replace(' ', '_')
                                target = item.end_node.get('name', '').replace(' ', '_')
                                edges.append({'id': f"{source}_{target}", 'source': source, 'target': target, 'label': 'R'})
                    result = {'nodes': nodes, 'edges': edges}
                    logger.debug("Manual query result: %s", json.dumps(result, indent=2))
            except Exception as e:
                error = f'Query error: {str(e)}'
                logger.error("Manual query execution failed: %s", str(e))

    logger.debug("Rendering manual_query.html with error: %s, result: %s", error, result is not None)
    return render(request, 'dashboard/manual_query.html', {
        'result_json': json.dumps(result) if result else None,
        'error': error,
    })

@login_required
def admin_queries(request):
    """Manage predefined queries."""
    logger.debug("Entering admin_queries view with request method: %s", request.method)
    if request.method == 'POST':
        query_name = request.POST.get('query_name', '').strip()
        query_text = request.POST.get('query_text', '').strip()
        logger.debug("Received POST data - query_name: %s, query_text: %s", query_name, query_text)
        if not query_name or not query_text:
            messages.error(request, 'Please provide both a query name and the query text.')
            logger.warning("Validation failed: Query name or text missing")
        else:
            try:
                PredefinedQuery.objects.create(name=query_name, query=query_text)
                messages.success(request, 'Predefined query added successfully.')
                logger.info("Predefined query added: %s", query_name)
            except Exception as e:
                messages.error(request, f'Error adding query: {str(e)}')
                logger.error("Error adding predefined query: %s", str(e))
        return redirect('admin_queries')

    predefined_queries = PredefinedQuery.objects.all()
    logger.debug("Rendering admin_queries.html with predefined_queries: %s", predefined_queries)
    return render(request, 'dashboard/admin_queries.html', {'predefined_queries': predefined_queries})

@login_required
def delete_predefined_query(request, query_id):
    """Delete a predefined query."""
    logger.debug("Entering delete_predefined_query view with query_id: %d", query_id)
    try:
        query = PredefinedQuery.objects.get(id=query_id)
        query.delete()
        messages.success(request, 'Predefined query deleted successfully.')
        logger.info("Predefined query deleted: %d", query_id)
    except PredefinedQuery.DoesNotExist:
        messages.error(request, 'Query not found.')
        logger.warning("Query not found: %d", query_id)
    except Exception as e:
        messages.error(request, f'Error deleting query: {str(e)}')
        logger.error("Error deleting predefined query: %s", str(e))
    return redirect('admin_queries')

def predefined_query_result(request, query_id):
    """Execute a predefined query and display the result."""
    logger.debug("Entering predefined_query_result view with query_id: %d", query_id)
    try:
        query_obj = PredefinedQuery.objects.get(id=query_id)
        logger.debug("Retrieved predefined query: %s", query_obj.query)
        with driver.session() as session:
            result = session.run(query_obj.query)
            nodes = []
            edges = []
            for record in result:
                for item in record.values():
                    if isinstance(item, dict):
                        if 'name' in item:
                            node_id = item['name'].replace(' ', '_')
                            nodes.append({'id': node_id, 'label': item['name']})
                    elif hasattr(item, 'start_node') and hasattr(item, 'end_node'):
                        source = item.start_node.get('name', '').replace(' ', '_')
                        target = item.end_node.get('name', '').replace(' ', '_')
                        edges.append({'id': f"{source}_{target}", 'source': source, 'target': target, 'label': 'R'})
            result = {'nodes': nodes, 'edges': edges}
            logger.debug("Predefined query result: %s", json.dumps(result, indent=2))
    except PredefinedQuery.DoesNotExist:
        messages.error(request, 'Query not found.')
        logger.warning("Query not found: %d", query_id)
        return redirect('home')
    except Exception as e:
        messages.error(request, f'Query error: {str(e)}')
        logger.error("Predefined query execution failed: %s", str(e))
        return redirect('home')

    logger.debug("Rendering predefined_query_result.html with result")
    return render(request, 'dashboard/predefined_query_result.html', {
        'query': query_obj,
        'result_json': json.dumps(result) if result else None
    })

def register(request):
    """Register a new user."""
    logger.debug("Entering register view with request method: %s", request.method)
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        logger.debug("Received registration form data")
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Registration successful.')
            logger.info("User registered successfully: %s", user.username)
            return redirect('home')
        else:
            logger.warning("Registration form invalid: %s", form.errors)
    else:
        form = UserCreationForm()
    logger.debug("Rendering register.html with form")
    return render(request, 'dashboard/register.html', {'form': form})

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
    """Select relationships between nodes."""
    logger.debug("Entering select_relationships view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    logger.debug("Retrieved nodes from session: %s", nodes)
    if not nodes:
        messages.error(request, 'No nodes found. Please start over.')
        logger.warning("Session data missing: No nodes found")
        return redirect('add_nodes')

    all_nodes = nodes + get_existing_nodes()
    logger.debug("Combined all nodes: %s", all_nodes)
    if request.method == 'POST':
        relationships = []
        for node1 in all_nodes:
            for node2 in all_nodes:
                if node1 != node2:
                    relationship_key = f'relationship_{node1}_{node2}'
                    if request.POST.get(relationship_key) == 'on':
                        relationships.append((node1, node2))
        logger.debug("Selected relationships: %s", relationships)
        request.session['relationships'] = relationships
        return redirect('confirm_relationships')

    logger.debug("Rendering select_relationships.html with all_nodes: %s", all_nodes)
    return render(request, 'dashboard/select_relationships.html', {'all_nodes': all_nodes})

def confirm_relationships(request):
    """Confirm relationships before saving."""
    logger.debug("Entering confirm_relationships view with request method: %s", request.method)
    nodes = request.session.get('nodes', [])
    relationships = request.session.get('relationships', [])
    logger.debug("Retrieved session data - nodes: %s, relationships: %s", nodes, relationships)
    if not nodes or not relationships:
        messages.error(request, 'Session data missing. Please start over.')
        logger.warning("Session data missing: nodes or relationships not found")
        return redirect('add_nodes')

    if request.method == 'POST':
        action = request.POST.get('action')
        logger.debug("Received action: %s", action)
        if action == 'confirm':
            cypher_query = "CREATE "
            cypher_query += ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in nodes])
            cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in nodes])
            cypher_query += "\nCREATE " + ", CREATE ".join(
                [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships]
            )
            logger.debug("Constructed Cypher query for execution: %s", cypher_query)
            try:
                with driver.session() as session:
                    session.run(cypher_query)
                messages.success(request, 'Relationships created successfully.')
                logger.info("Relationships created successfully")
            except Exception as e:
                messages.error(request, f'Error creating relationships: {str(e)}')
                logger.error("Error creating relationships: %s", str(e))
            finally:
                request.session.pop('nodes', None)
                request.session.pop('relationships', None)
                logger.debug("Cleared session data")
            return redirect('home')
        else:
            messages.info(request, 'Operation cancelled.')
            logger.info("Operation cancelled by user")
            return redirect('home')

    logger.debug("Rendering confirm_relationships.html")
    return render(request, 'dashboard/confirm_relationships.html', {
        'nodes': nodes,
        'relationships': relationships,
    })

@login_required
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
                    with driver.session() as session:
                        query = """
                            MATCH (start:Node)
                            WHERE start.name = $node_name
                            MATCH (start)-[*1..$depth]->(end:Node)
                            WHERE end <> start
                            RETURN DISTINCT end.name AS connected_node_names
                        """
                        logger.debug("Constructed Cypher query: %s", query)
                        logger.debug("Parameters - node_name: %s, depth: %d", node_name, depth)

                        result = session.run(query, node_name=node_name, depth=depth)
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
                            'nodes': [{'id': data['id'], 'label': data['label']} for data in nodes.values()],
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