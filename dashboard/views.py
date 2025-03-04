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

# Initialize Neo4j driver (unchanged)
driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))

logger = logging.getLogger(__name__)

def get_existing_nodes():
    try:
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            return [record["name"] for record in result]
    except Exception as e:
        logger.error(f"Neo4j error in get_existing_nodes: {e}")
        return []

@csrf_exempt  # Note: For simplicity; use CSRF token in production
def check_node_duplicate(request):
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        node_name = request.POST.get('node_name', '').strip()
        if node_name:
            existing_nodes = get_existing_nodes()
            is_duplicate = node_name in existing_nodes
            return JsonResponse({'exists': is_duplicate, 'message': f"Node '{node_name}' already exists" if is_duplicate else ''})
        return JsonResponse({'exists': False, 'message': 'Invalid node name'})
    return JsonResponse({'exists': False, 'message': 'Invalid request'})

@staff_member_required
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'User created successfully.')
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'dashboard/register.html', {'form': form})

def home(request):
    options = [
        {'name': 'Add Nodes', 'url': 'add_nodes'},
        {'name': 'Manual Query', 'url': 'manual_query'},
        {'name': 'Admin Queries', 'url': 'admin_queries'},
    ]
    predefined_queries = PredefinedQuery.objects.all() if request.user.is_authenticated else None
    return render(request, 'dashboard/home.html', {'options': options, 'predefined_queries': predefined_queries})

@login_required
def add_nodes(request):
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

@login_required
def relationship_option(request):
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

@login_required
def input_existing_nodes(request):
    existing_nodes_list = get_existing_nodes()
    if request.method == 'POST':
        existing_nodes_input = request.POST.get('existing_nodes', '')
        existing_nodes_input = [node.strip() for node in existing_nodes_input.split('\n') if node.strip()]
        invalid_nodes = [node for node in existing_nodes_input if node not in existing_nodes_list]
        valid_existing_nodes = [node for node in existing_nodes_input if node in existing_nodes_list]
        if invalid_nodes:
            messages.error(request, 'Some nodes are invalid.')
            return render(request, 'dashboard/input_existing_nodes.html', {
                'invalid_nodes': invalid_nodes,
                'existing_nodes_list': existing_nodes_list
            })
        if not valid_existing_nodes:
            messages.error(request, 'Please select at least one valid existing node.')
            return render(request, 'dashboard/input_existing_nodes.html', {'existing_nodes_list': existing_nodes_list})
        request.session['existing_nodes'] = valid_existing_nodes
        return redirect('define_relations_with_existing_nodes')
    return render(request, 'dashboard/input_existing_nodes.html', {'existing_nodes_list': existing_nodes_list})

@login_required
def define_relations_with_existing_nodes(request):
    new_nodes = request.session.get('nodes', [])
    existing_nodes = request.session.get('existing_nodes', [])
    if not new_nodes:
        messages.error(request, 'Session expired. Please start over.')
        return redirect('add_nodes')
    if request.method == 'POST':
        relations = request.POST.getlist('relations')
        relations_data = []
        try:
            for relation in relations:
                new_node, existing_node = relation.split(',')
                if new_node in new_nodes and existing_node in existing_nodes:
                    relations_data.append({'from': new_node, 'to': existing_node})
                else:
                    raise ValueError("Invalid node in relationship.")
        except ValueError:
            messages.error(request, 'Invalid relationship format.')
            return render(request, 'dashboard/define_relations_with_existing_nodes.html', {
                'new_nodes': new_nodes,
                'existing_nodes': existing_nodes
            })
        request.session['relations_data'] = relations_data
        return redirect('confirm_relations')
    return render(request, 'dashboard/define_relations_with_existing_nodes.html', {
        'new_nodes': new_nodes,
        'existing_nodes': existing_nodes
    })

@login_required
def define_new_node_relations(request):
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

@login_required
def confirm_relations(request):
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

@login_required
def manual_query(request):
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

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_queries(request):
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
    try:
        query = PredefinedQuery.objects.get(id=query_id)
        query.delete()
        messages.success(request, 'Query deleted successfully.')
    except PredefinedQuery.DoesNotExist:
        messages.error(request, 'Query not found.')
    return redirect('admin_queries')

@login_required
def predefined_query_result(request, query_id):
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

def create_nodes_in_neo4j(nodes):
    with driver.session() as session:
        for node in nodes:
            session.run("MERGE (n:Node {name: $name})", name=node)

def create_relations_in_neo4j(relations_data):
    with driver.session() as session:
        for relation in relations_data:
            session.run("""
                MATCH (n1:Node {name: $from_node})
                MATCH (n2:Node {name: $to_node})
                MERGE (n1)-[:RELATED_TO]->(n2)
            """, from_node=relation['from'], to_node=relation['to'])

def get_existing_nodes():
    try:
        with driver.session() as session:
            result = session.run("MATCH (n:Node) RETURN n.name AS name")
            return [record["name"] for record in result]
    except Exception:
        return []

def process_value(value, nodes, edges):
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