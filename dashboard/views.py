import json
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path
from .models import SavedQuery, PredefinedQuery
from django.contrib.auth.forms import UserCreationForm
from django.contrib.admin.views.decorators import staff_member_required
import logging

# Initialize Neo4j driver
driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))

logger = logging.getLogger(__name__)

# Helper function to get existing nodes
def get_existing_nodes():
    """Retrieve all existing node names from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            return [record["name"] for record in result]
    except Exception as e:
        logger.error(f"Neo4j error in get_existing_nodes: {e}")
        return []

# AJAX endpoint to check for duplicate nodes
@csrf_exempt
def check_node_duplicate(request):
    """Handle AJAX requests to check if a node name exists."""
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        node_name = request.POST.get('node_name', '').strip()
        if node_name:
            existing_nodes = get_existing_nodes()
            is_duplicate = node_name in existing_nodes
            return JsonResponse({'exists': is_duplicate, 'message': f"Node '{node_name}' already exists" if is_duplicate else ''})
        return JsonResponse({'exists': False, 'message': 'Invalid node name'})
    return JsonResponse({'exists': False, 'message': 'Invalid request'})

# Staff-only registration view
@staff_member_required
def register(request):
    """Handle user registration for staff members."""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'User created successfully.')
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'dashboard/register.html', {'form': form})

# Home view with navigation options
def home(request):
    """Display the home page with navigation options."""
    options = [
        {'name': 'Add Nodes', 'url': 'add_nodes'},
        {'name': 'Manual Query', 'url': 'manual_query'},
        {'name': 'Admin Queries', 'url': 'admin_queries'},
    ]
    predefined_queries = PredefinedQuery.objects.all() if request.user.is_authenticated else None
    return render(request, 'dashboard/home.html', {'options': options, 'predefined_queries': predefined_queries})

# View to add new nodes with duplicate checking
@login_required
def add_nodes(request):
    """Handle the addition of new nodes with duplicate checking."""
    if request.method == 'POST':
        nodes = request.POST.getlist('nodes')
        nodes = [node.strip() for node in nodes if node.strip()]
        if not nodes:
            messages.error(request, 'Please enter at least one node name.')
            return render(request, 'dashboard/add_nodes.html')
        
        existing_nodes = get_existing_nodes()
        duplicate_nodes = [node for node in nodes if node in existing_nodes]
        if duplicate_nodes:
            messages.error(request, f'The following nodes already exist: {", ".join(duplicate_nodes)}. Please use unique names.')
            return render(request, 'dashboard/add_nodes.html', {'duplicate_nodes': duplicate_nodes})
        
        request.session['nodes'] = nodes
        return redirect('relationship_option')
    return render(request, 'dashboard/add_nodes.html')

# View to choose relationship option (Yes/No)
@login_required
def relationship_option(request):
    """Allow user to choose if nodes relate to existing database nodes."""
    if request.method == 'POST':
        option = request.POST.get('option')
        if option == 'yes':
            return redirect('input_existing_nodes')
        elif option == 'no':
            return redirect('define_new_node_relations')
        else:
            messages.error(request, 'Invalid option selected.')
            return render(request, 'dashboard/relationship_option.html')
    return render(request, 'dashboard/relationship_option.html')

# View to input existing nodes for "Yes" path (Step 1 and 2)
@login_required
def input_existing_nodes(request):
    """Display pre-entered nodes and allow selection of existing nodes."""
    existing_nodes_list = get_existing_nodes()
    nodes = request.session.get('nodes', [])
    if not nodes:
        messages.error(request, 'No nodes entered in the previous step. Please start over.')
        return redirect('add_nodes')
    
    if request.method == 'POST':
        existing_nodes = request.POST.getlist('existing_nodes')
        existing_nodes = [node.strip() for node in existing_nodes if node.strip()]
        
        if not existing_nodes:
            messages.error(request, 'Please select at least one existing node to relate.')
            return render(request, 'dashboard/input_existing_nodes.html', {
                'existing_nodes_list': existing_nodes_list,
                'nodes': nodes
            })

        # Validate selected existing nodes
        invalid_nodes = [node for node in existing_nodes if node not in existing_nodes_list]
        valid_existing_nodes = [node for node in existing_nodes if node in existing_nodes_list]
        if invalid_nodes:
            messages.error(request, 'Some selected nodes are invalid.')
            return render(request, 'dashboard/input_existing_nodes.html', {
                'existing_nodes_list': existing_nodes_list,
                'nodes': nodes,
                'invalid_nodes': invalid_nodes
            })

        request.session['existing_nodes'] = valid_existing_nodes
        return redirect('select_relationships')

    return render(request, 'dashboard/input_existing_nodes.html', {
        'existing_nodes_list': existing_nodes_list,
        'nodes': nodes
    })

# View to select relationships (Step 3)
@login_required
def select_relationships(request):
    """Allow user to select relationships between all nodes."""
    nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    if not nodes or not existing_nodes:
        messages.error(request, 'Session data missing. Please start over.')
        return redirect('add_nodes')

    all_nodes = nodes + existing_nodes
    if request.method == 'POST':
        relationships = request.POST.getlist('relationships')
        relationships = [rel.split(',') for rel in relationships]
        request.session['relationships'] = relationships
        return redirect('confirm_relationships')

    return render(request, 'dashboard/select_relationships.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'all_nodes': all_nodes
    })

@login_required
def confirm_relationships(request):
    """Display and confirm the Cypher query before execution."""
    nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    relationships = request.session.get('relationships', [])
    if not nodes or not existing_nodes or not relationships:
        messages.error(request, 'Session data missing. Please start over.')
        return redirect('add_nodes')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'confirm':
            # Construct full Cypher query
            cypher_query = ""
            new_nodes_to_create = [node for node in nodes if node not in get_existing_nodes()]
            if new_nodes_to_create:
                cypher_query += "CREATE " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in new_nodes_to_create])
                cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in new_nodes_to_create])
            if existing_nodes:
                cypher_query += "\nMATCH " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in existing_nodes])
            if relationships:
                # Fix: Use a single CREATE clause with comma-separated patterns
                relationship_clauses = "\nCREATE " + ", ".join(
                    [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships
                     if rel[0] in nodes + existing_nodes and rel[1] in nodes + existing_nodes]
                )
                cypher_query += relationship_clauses

            try:
                with driver.session() as session:
                    session.run(cypher_query)
                messages.success(request, 'Nodes and relationships created successfully.')
            except Exception as e:
                messages.error(request, f'Error creating nodes and relationships: {str(e)}')
                # Log the full query for debugging
                print(f"Failed Cypher Query: {cypher_query}")
            finally:
                request.session.pop('nodes', None)
                request.session.pop('existing_nodes', None)
                request.session.pop('relationships', None)
            return redirect('home')
        else:
            messages.info(request, 'Operation cancelled.')
            return redirect('home')

    # Display query for confirmation (same correction)
    cypher_query = "CREATE "
    new_nodes_to_create = [node for node in nodes if node not in get_existing_nodes()]
    if new_nodes_to_create:
        cypher_query += ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in new_nodes_to_create])
        cypher_query += "\nWITH " + ", ".join([node.replace(' ', '_') for node in new_nodes_to_create])
    if existing_nodes:
        cypher_query += "\nMATCH " + ", ".join([f"({node.replace(' ', '_')}:Node {{name: '{node}'}})" for node in existing_nodes])
    if relationships:
        # Fix: Use a single CREATE clause with comma-separated patterns
        relationship_clauses = "\nCREATE " + ", ".join(
            [f"({rel[0].replace(' ', '_')})-[:R]->({rel[1].replace(' ', '_')})" for rel in relationships
             if rel[0] in nodes + existing_nodes and rel[1] in nodes + existing_nodes]
        )
        cypher_query += relationship_clauses

    return render(request, 'dashboard/confirm_relationships.html', {
        'nodes': nodes,
        'existing_nodes': existing_nodes,
        'relationships': relationships,
        'cypher_query': cypher_query
    })

# View to define relationships between new nodes (for "No" path)
@login_required
def define_new_node_relations(request):
    """Define relationships between new nodes for the 'No' path."""
    new_nodes = request.session.get('nodes', [])
    if not new_nodes:
        messages.error(request, 'Session expired. Please start over.')
        return redirect('add_nodes')
    if request.method == 'POST':
        relations = request.POST.getlist('relations')
        relations_data = []
        try:
            for relation in relations:
                node1, node2 = relation.split(',')
                if node1 in new_nodes and node2 in new_nodes:
                    relations_data.append({'from': node1, 'to': node2})
                else:
                    raise ValueError("Invalid node in relationship.")
        except ValueError:
            messages.error(request, 'Invalid relationship format.')
            return render(request, 'dashboard/define_new_node_relations.html', {'new_nodes': new_nodes})
        request.session['relations_data'] = relations_data
        return redirect('confirm_relations')
    return render(request, 'dashboard/define_new_node_relations.html', {'new_nodes': new_nodes})

# View to confirm and create nodes/relationships (for "No" path)
@login_required
def confirm_relations(request):
    """Confirm and create nodes and relationships for the 'No' path."""
    relations_data = request.session.get('relations_data', [])
    new_nodes = request.session.get('nodes', [])
    if not new_nodes:
        messages.error(request, 'Session expired. Please start over.')
        return redirect('add_nodes')
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'confirm':
            try:
                create_nodes_in_neo4j(new_nodes)
                create_relations_in_neo4j(relations_data)
                messages.success(request, 'Nodes and relationships imported successfully.')
            except Exception as e:
                messages.error(request, f'Error importing data: {str(e)}')
                return render(request, 'dashboard/confirm_relations.html', {'relations_data': relations_data})
            finally:
                request.session.pop('nodes', None)
                request.session.pop('relations_data', None)
                request.session.pop('existing_nodes', None)
            return redirect('home')
        else:
            messages.info(request, 'Operation cancelled.')
            return redirect('home')
    return render(request, 'dashboard/confirm_relations.html', {'relations_data': relations_data})

# View for manual query execution
@login_required
def manual_query(request):
    """Handle manual query execution and display results."""
    error = None
    query_text = ''
    result = None
    if request.method == 'POST':
        query_text = request.POST.get('query', '').strip()
        if not query_text:
            error = 'Please enter a query.'
        else:
            try:
                with driver.session() as session:
                    neo4j_result = session.run(query_text)
                    nodes = {}
                    edges = []
                    for record in neo4j_result:
                        for value in record.values():
                            if isinstance(value, Node):
                                process_node(value, nodes)
                            elif isinstance(value, Relationship):
                                process_relationship(value, edges)
                            elif isinstance(value, Path):
                                for node in value.nodes:
                                    process_node(node, nodes)
                                for rel in value.relationships:
                                    process_relationship(rel, edges)
                            elif isinstance(value, list):
                                for item in value:
                                    process_value(item, nodes, edges)
                    result = {
                        'nodes': [{'id': node['data']['id'], 'label': node['data']['label'], 'properties': node['data']['properties']} for node in nodes.values()],
                        'edges': [{'id': edge['data']['id'], 'source': edge['data']['source'], 'target': edge['data']['target'], 'label': edge['data']['label'], 'properties': edge['data']['properties']} for edge in edges]
                    }
                    print("Result JSON:", json.dumps(result, indent=2))
                    SavedQuery.objects.create(query=query_text)
            except Exception as e:
                error = f'Query error: {str(e)}'
    return render(request, 'dashboard/manual_query.html', {
        'result_json': json.dumps(result) if result else None,
        'error': error,
        'query': query_text,
        'saved_queries': SavedQuery.objects.all()[:5]
    })

# Admin views for query management
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_queries(request):
    """Manage predefined queries for admin users."""
    if request.method == 'POST':
        query_name = request.POST.get('query_name')
        query_text = request.POST.get('query_text')
        if query_name and query_text:
            try:
                PredefinedQuery.objects.create(name=query_name, query=query_text)
                messages.success(request, 'Query created successfully.')
            except Exception as e:
                messages.error(request, f'Error creating query: {str(e)}')
        return redirect('admin_queries')
    queries = PredefinedQuery.objects.all()[:3]
    return render(request, 'dashboard/admin_queries.html', {'queries': queries})

@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def delete_predefined_query(request, query_id):
    """Delete a predefined query for admin users."""
    try:
        query = PredefinedQuery.objects.get(id=query_id)
        query.delete()
        messages.success(request, 'Query deleted successfully.')
    except PredefinedQuery.DoesNotExist:
        messages.error(request, 'Query not found.')
    return redirect('admin_queries')

@login_required
def predefined_query_result(request, query_id):
    """Display results of a predefined query."""
    try:
        query = PredefinedQuery.objects.get(id=query_id)
        error = None
        result = None
        try:
            with driver.session() as session:
                neo4j_result = session.run(query.query)
                nodes = {}
                edges = []
                for record in neo4j_result:
                    for value in record.values():
                        if isinstance(value, Node):
                            process_node(value, nodes)
                        elif isinstance(value, Relationship):
                            process_relationship(value, edges)
                        elif isinstance(value, Path):
                            for node in value.nodes:
                                process_node(node, nodes)
                            for rel in value.relationships:
                                process_relationship(rel, edges)
                        elif isinstance(value, list):
                            for item in value:
                                process_value(item, nodes, edges)
                result = {
                    'nodes': [{'id': node['data']['id'], 'label': node['data']['label'], 'properties': node['data']['properties']} for node in nodes.values()],
                    'edges': [{'id': edge['data']['id'], 'source': edge['data']['source'], 'target': edge['data']['target'], 'label': edge['data']['label'], 'properties': edge['data']['properties']} for edge in edges]
                }
                print("Predefined Query Result JSON:", json.dumps(result, indent=2))
        except Exception as e:
            error = f'Query error: {str(e)}'
        return render(request, 'dashboard/predefined_query_result.html', {
            'result_json': json.dumps(result) if result else None,
            'error': error,
            'query_name': query.name,
            'saved_queries': SavedQuery.objects.all()[:5]
        })
    except PredefinedQuery.DoesNotExist:
        return render(request, 'dashboard/base.html', {'error': 'Query not found.'})

# Helper functions for Neo4j operations
def create_nodes_in_neo4j(nodes):
    """Create new nodes in Neo4j using MERGE to avoid duplicates."""
    with driver.session() as session:
        for node in nodes:
            session.run("MERGE (n:Node {name: $name})", name=node)

def create_relations_in_neo4j(relations_data):
    """Create relationships between nodes in Neo4j."""
    with driver.session() as session:
        for relation in relations_data:
            session.run("""
                MATCH (n1:Node {name: $from_node})
                MATCH (n2:Node {name: $to_node})
                MERGE (n1)-[:R]->(n2)
            """, from_node=relation['from'], to_node=relation['to'])

def get_existing_nodes():
    """Retrieve all existing node names from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            return [record["name"] for record in result]
    except Exception:
        return []

def process_value(value, nodes, edges):
    """Process Neo4j query results into nodes and edges."""
    if isinstance(value, Node):
        process_node(value, nodes)
    elif isinstance(value, Relationship):
        process_relationship(value, edges)
    elif isinstance(value, Path):
        for node in value.nodes:
            process_node(node, nodes)
        for rel in value.relationships:
            process_relationship(rel, edges)
    elif isinstance(value, list):
        for item in value:
            process_value(item, nodes, edges)

def process_node(node, nodes):
    """Process a single node into the nodes dictionary."""
    node_id = str(node.id)
    if node_id not in nodes:
        nodes[node_id] = {
            'data': {
                'id': node_id,
                'label': node.get('name', list(node.labels)[0] if node.labels else 'Node'),
                'properties': dict(node.items())
            }
        }
    return nodes[node_id]['data']

def process_relationship(rel, edges):
    """Process a single relationship into the edges list."""
    edge = {
        'data': {
            'id': str(rel.id),
            'source': str(rel.start_node.id),
            'target': str(rel.end_node.id),
            'label': rel.type,
            'properties': dict(rel.items())
        }
    }
    edges.append(edge)