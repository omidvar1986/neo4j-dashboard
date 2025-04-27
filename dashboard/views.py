import logging
import json
import os
from django.shortcuts import render, redirect
from django.http import JsonResponse
from neo4j import GraphDatabase
from dotenv import load_dotenv
from neo4j.graph import Node, Relationship, Path
from .models import AdminQuery
from .neo4j_driver import get_neo4j_driver, close_neo4j_driver
from django.contrib import messages

# Load environment variables from .env file
load_dotenv()

# Initialize logger
logger = logging.getLogger('dashboard')

# Neo4j connection setup
uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
user = os.getenv('NEO4J_USER', 'neo4j')
password = os.getenv('NEO4J_PASSWORD', 'Milad1986')

def get_driver():
    """Create a Neo4j driver instance."""
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        logger.info("Established Neo4j connection at %s", uri)
        return driver
    except Exception as e:
        logger.error("Failed to establish Neo4j connection at %s: %s", uri, str(e))
        raise

# Helper function for safe Cypher queries
def is_safe_query(query):
    """Check if a Cypher query is safe to execute."""
    unsafe_keywords = ['DELETE', 'DETACH', 'CREATE', 'SET', 'REMOVE']
    query_upper = query.upper()
    return not any(keyword in query_upper for keyword in unsafe_keywords)

# Helper functions for PredefinedQuery
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

def home(request):
    """Render the home page with options."""
    logger.debug("Entering home view")
    return render(request, 'dashboard/home.html', {})

def get_existing_nodes_view(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        existing_nodes = get_existing_nodes()
        return JsonResponse(list(existing_nodes), safe=False)
    return JsonResponse({'error': 'Invalid request'}, status=400)

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
                close_neo4j_driver()
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







def is_safe_query(cypher_query):
    """
    Check if the Cypher query is safe (only MATCH and RETURN allowed).
    """
    query_upper = cypher_query.upper()
    allowed_keywords = ['MATCH', 'RETURN', 'WHERE', 'WITH', 'UNWIND', 'LIMIT', 'SKIP', 'ORDER BY']
    disallowed_keywords = ['CREATE', 'DELETE', 'REMOVE', 'SET', 'MERGE', 'DROP', 'CALL']
    
    for keyword in disallowed_keywords:
        if keyword in query_upper:
            return False
    
    has_match_or_return = 'MATCH' in query_upper or 'RETURN' in query_upper
    return has_match_or_return

def manual_queries(request):
    logger.debug("Entering manual_queries view with method: %s", request.method)

    graph_data = {'nodes': [], 'edges': []}
    cypher_query = ""

    if request.method == 'POST':
        action = request.POST.get('action')
        cypher_query = request.POST.get('cypher_query', '').strip()

        if action == 'clear':
            logger.info("User cleared the query and graph")
            return redirect('dashboard:manual_queries')

        if action == 'execute':
            if not cypher_query:
                logger.warning("No Cypher query provided")
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': 'Please enter a Cypher query.',
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
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
                })

            try:
                driver = get_driver()
                if driver is None:
                    logger.error("Neo4j driver is not initialized")
                    return render(request, 'dashboard/manual_queries.html', {
                        'error_message': 'Neo4j driver is not initialized. Please check configuration.',
                        'graph_data': graph_data,
                        'cypher_query': cypher_query,
                        'nodes_json': json.dumps([]),
                        'edges_json': json.dumps([]),
                    })

                with driver.session() as session:
                    # مرحله ۱: اجرای کوئری اصلی و جمع‌آوری نودها
                    result = session.run(cypher_query)
                    node_id_map = {}
                    node_counter = 0
                    node_internal_ids = set()

                    records = list(result)
                    logger.debug("Number of records returned: %d", len(records))

                    for record in records:
                        logger.debug("Record values: %s", record.values())
                        for value in record.values():
                            # پردازش نودها
                            if isinstance(value, Node):
                                node_id = value.get('name', f"Node_{node_counter}")
                                node_counter += 1
                                node_internal_ids.add(id(value))
                                node_id_map[id(value)] = node_id
                                if not any(node['id'] == node_id for node in graph_data['nodes']):
                                    logger.debug("Adding node: %s (internal id: %s)", node_id, id(value))
                                    labels = list(value.labels)  # Extract labels
                                    properties = dict(value)  # Extract all properties
                                    graph_data['nodes'].append({
                                        'id': node_id,
                                        'label': node_id,
                                        'labels': labels,  # Add labels
                                        'properties': properties,  # Add properties
                                    })
                            # پردازش مسیرها
                            elif isinstance(value, Path):
                                for node in value.nodes:
                                    node_id = node.get('name', f"Node_{node_counter}")
                                    node_counter += 1
                                    node_internal_ids.add(id(node))
                                    node_id_map[id(node)] = node_id
                                    if not any(node['id'] == node_id for node in graph_data['nodes']):
                                        logger.debug("Adding node from path: %s (internal id: %s)", node_id, id(node))
                                        labels = list(node.labels)
                                        properties = dict(node)
                                        graph_data['nodes'].append({
                                            'id': node_id,
                                            'label': node_id,
                                            'labels': labels,
                                            'properties': properties,
                                        })
                            # پردازش لیست‌ها
                            elif isinstance(value, (list, tuple)):
                                for item in value:
                                    if isinstance(item, Node):
                                        node_id = item.get('name', f"Node_{node_counter}")
                                        node_counter += 1
                                        node_internal_ids.add(id(item))
                                        node_id_map[id(item)] = node_id
                                        if not any(node['id'] == node_id for node in graph_data['nodes']):
                                            logger.debug("Adding node from list: %s (internal id: %s)", node_id, id(item))
                                            labels = list(item.labels)
                                            properties = dict(item)
                                            graph_data['nodes'].append({
                                                'id': node_id,
                                                'label': node_id,
                                                'labels': labels,
                                                'properties': properties,
                                            })
                                    elif isinstance(item, Path):
                                        for node in item.nodes:
                                            node_id = node.get('name', f"Node_{node_counter}")
                                            node_counter += 1
                                            node_internal_ids.add(id(node))
                                            node_id_map[id(node)] = node_id
                                            if not any(node['id'] == node_id for node in graph_data['nodes']):
                                                logger.debug("Adding node from path in list: %s (internal id: %s)", node_id, id(node))
                                                labels = list(node.labels)
                                                properties = dict(node)
                                                graph_data['nodes'].append({
                                                    'id': node_id,
                                                    'label': node_id,
                                                    'labels': labels,
                                                    'properties': properties,
                                                })

                    # اگه هیچ نودی پیدا نشد
                    if not node_internal_ids:
                        logger.warning("No nodes found with query: %s", cypher_query)
                        return render(request, 'dashboard/manual_queries.html', {
                            'error_message': 'No nodes found. Try a different query or check the labels.',
                            'graph_data': graph_data,
                            'cypher_query': cypher_query,
                            'nodes_json': json.dumps([]),
                            'edges_json': json.dumps([]),
                        })

                    # محدود کردن تعداد نودها برای جلوگیری از شلوغی
                    MAX_NODES = 50
                    if len(graph_data['nodes']) > MAX_NODES:
                        logger.warning("Too many nodes returned: %d. Limiting to %d.", len(graph_data['nodes']), MAX_NODES)
                        graph_data['nodes'] = graph_data['nodes'][:MAX_NODES]
                        node_id_map = {k: v for k, v in list(node_id_map.items())[:MAX_NODES]}
                        node_internal_ids = set(list(node_internal_ids)[:MAX_NODES])

                    # مرحله ۲: پیدا کردن همه نودها و رابطه‌های مرتبط
                    logger.debug("Node internal IDs: %s", node_internal_ids)
                    if node_internal_ids:
                        relationship_query = """
                        MATCH (n)-[r]-(m)
                        WHERE id(n) IN $node_ids OR id(m) IN $node_ids
                        RETURN n, r, m
                        LIMIT 100
                        """
                        # Comment moved outside the query string
                        # -- Limit relationships to avoid overload
                        relationship_result = session.run(relationship_query, node_ids=list(node_internal_ids))
                        relationships_found = 0
                        for rel_record in relationship_result:
                            n = rel_record['n']
                            r = rel_record['r']
                            m = rel_record['m']
                            logger.debug("Relationship found: %s -[%s]-> %s", n.get('name'), r.type, m.get('name'))
                            relationships_found += 1

                            # اضافه کردن نود n
                            node_id_n = node_id_map.get(id(n))
                            if not node_id_n and len(graph_data['nodes']) < MAX_NODES:
                                node_id_n = n.get('name', f"Node_{node_counter}")
                                node_counter += 1
                                node_id_map[id(n)] = node_id_n
                                if not any(node['id'] == node_id_n for node in graph_data['nodes']):
                                    logger.debug("Adding related node n: %s (internal id: %s)", node_id_n, id(n))
                                    labels = list(n.labels)
                                    properties = dict(n)
                                    graph_data['nodes'].append({
                                        'id': node_id_n,
                                        'label': node_id_n,
                                        'labels': labels,
                                        'properties': properties,
                                    })

                            # اضافه کردن نود m
                            node_id_m = node_id_map.get(id(m))
                            if not node_id_m and len(graph_data['nodes']) < MAX_NODES:
                                node_id_m = m.get('name', f"Node_{node_counter}")
                                node_counter += 1
                                node_id_map[id(m)] = node_id_m
                                if not any(node['id'] == node_id_m for node in graph_data['nodes']):
                                    logger.debug("Adding related node m: %s (internal id: %s)", node_id_m, id(m))
                                    labels = list(m.labels)
                                    properties = dict(m)
                                    graph_data['nodes'].append({
                                        'id': node_id_m,
                                        'label': node_id_m,
                                        'labels': labels,
                                        'properties': properties,
                                    })

                            # اضافه کردن رابطه
                            if isinstance(r, Relationship):
                                source_id = node_id_map.get(id(r.start_node))
                                target_id = node_id_map.get(id(r.end_node))
                                if source_id and target_id:
                                    edge_id = f"edge-{len(graph_data['edges'])}"
                                    if not any(e['id'] == edge_id for e in graph_data['edges']):
                                        logger.debug("Adding edge: %s -> %s with label %s", source_id, target_id, r.type)
                                        graph_data['edges'].append({
                                            'id': edge_id,
                                            'source': source_id,
                                            'target': target_id,
                                            'label': r.type,
                                        })
                                else:
                                    logger.warning("Could not find source or target for relationship: %s", r)
                        logger.debug("Total relationships found: %d", relationships_found)

                    # مرحله ۳: پردازش رابطه‌های مستقیم از کوئری
                    for record in records:
                        for value in record.values():
                            if isinstance(value, Relationship):
                                source_id = node_id_map.get(id(value.start_node))
                                target_id = node_id_map.get(id(value.end_node))
                                if source_id and target_id:
                                    edge_id = f"edge-{len(graph_data['edges'])}"
                                    if not any(e['id'] == edge_id for e in graph_data['edges']):
                                        logger.debug("Adding edge from query: %s -> %s with label %s", source_id, target_id, value.type)
                                        graph_data['edges'].append({
                                            'id': edge_id,
                                            'source': source_id,
                                            'target': target_id,
                                            'label': value.type,
                                        })
                            elif isinstance(value, Path):
                                for rel in value.relationships:
                                    source_id = node_id_map.get(id(rel.start_node))
                                    target_id = node_id_map.get(id(rel.end_node))
                                    if source_id and target_id:
                                        edge_id = f"edge-{len(graph_data['edges'])}"
                                        if not any(e['id'] == edge_id for e in graph_data['edges']):
                                            logger.debug("Adding edge from path: %s -> %s with label %s", source_id, target_id, rel.type)
                                            graph_data['edges'].append({
                                                'id': edge_id,
                                                'source': source_id,
                                                'target': target_id,
                                                'label': rel.type,
                                            })
                            elif isinstance(value, (list, tuple)):
                                for item in value:
                                    if isinstance(item, Relationship):
                                        source_id = node_id_map.get(id(item.start_node))
                                        target_id = node_id_map.get(id(item.end_node))
                                        if source_id and target_id:
                                            edge_id = f"edge-{len(graph_data['edges'])}"
                                            if not any(e['id'] == edge_id for e in graph_data['edges']):
                                                logger.debug("Adding edge from list: %s -> %s with label %s", source_id, target_id, item.type)
                                                graph_data['edges'].append({
                                                    'id': edge_id,
                                                    'source': source_id,
                                                    'target': target_id,
                                                    'label': item.type,
                                                })
                                    elif isinstance(item, Path):
                                        for rel in item.relationships:
                                            source_id = node_id_map.get(id(rel.start_node))
                                            target_id = node_id_map.get(id(rel.end_node))
                                            if source_id and target_id:
                                                edge_id = f"edge-{len(graph_data['edges'])}"
                                                if not any(e['id'] == edge_id for e in graph_data['edges']):
                                                    logger.debug("Adding edge from path in list: %s -> %s with label %s", source_id, target_id, rel.type)
                                                    graph_data['edges'].append({
                                                        'id': edge_id,
                                                        'source': source_id,
                                                        'target': target_id,
                                                        'label': rel.type,
                                                    })

                    logger.debug("Final graph data: %s", graph_data)
                    logger.info("Successfully executed Cypher query: %s", cypher_query)
                    # Add more detailed logging for debugging
                    logger.debug("Nodes being sent to template: %s", graph_data['nodes'])
                    logger.debug("Edges being sent to template: %s", graph_data['edges'])
                    nodes_json = json.dumps(graph_data['nodes'])
                    edges_json = json.dumps(graph_data['edges'])
                    logger.debug("nodes_json: %s", nodes_json)
                    logger.debug("edges_json: %s", edges_json)
                    return render(request, 'dashboard/manual_queries.html', {
                        'success_message': 'Query executed successfully.',
                        'nodes_json': nodes_json,
                        'edges_json': edges_json,
                        'cypher_query': cypher_query,
                    })

            except Exception as e:
                logger.error("Error executing Cypher query: %s", str(e))
                return render(request, 'dashboard/manual_queries.html', {
                    'error_message': f"Error executing query: {str(e)}",
                    'graph_data': graph_data,
                    'cypher_query': cypher_query,
                    'nodes_json': json.dumps([]),
                    'edges_json': json.dumps([]),
                })

    logger.debug("Initial graph data on GET request: %s", graph_data)
    return render(request, 'dashboard/manual_queries.html', {
        'graph_data': graph_data,
        'cypher_query': cypher_query,
        'nodes_json': json.dumps([]),
        'edges_json': json.dumps([]),
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

def admin_queries(request):
    logger.debug("Entering admin_queries view with method: %s", request.method)

    # Get filter parameters from GET request
    is_active_filter = request.GET.get('is_active', 'true')
    created_by_filter = request.GET.get('created_by', None)

    # Build the query
    queries = AdminQuery.objects.all()
    if is_active_filter == 'true':
        queries = queries.filter(is_active=True)
    elif is_active_filter == 'false':
        queries = queries.filter(is_active=False)

    if created_by_filter:
        queries = queries.filter(created_by=created_by_filter)

    queries = queries.order_by('-created_at')

    # Handle form submission for query execution
    if request.method == 'POST':
        query_id = request.POST.get('query_id')
        try:
            query = AdminQuery.objects.get(id=query_id)
            # Check if query is safe
            if not is_safe_query(query.query_text):
                logger.warning("Unsafe Admin query detected: %s", query.query_text)
                return render(request, 'dashboard/admin_queries.html', {
                    'queries': queries,
                    'error': 'Unsafe query detected. Only MATCH and RETURN queries are allowed.',
                    'is_active_filter': is_active_filter,
                    'created_by_filter': created_by_filter,
                })
            with get_driver().session() as session:
                result = session.run(query.query_text)
                nodes = []
                edges = []
                seen_nodes = set()
                for record in result:
                    for item in record.values():
                        if isinstance(item, Node):
                            node_id = item.get('name', f"Node_{len(nodes)}")
                            if node_id not in seen_nodes:
                                nodes.append({'id': node_id, 'label': node_id, 'x': None, 'y': None})
                                seen_nodes.add(node_id)
                        elif isinstance(item, Relationship):
                            source_id = item.start_node.get('name', f"Node_{len(nodes)}")
                            target_id = item.end_node.get('name', f"Node_{len(nodes)+1}")
                            if source_id not in seen_nodes:
                                nodes.append({'id': source_id, 'label': source_id, 'x': None, 'y': None})
                                seen_nodes.add(source_id)
                            if target_id not in seen_nodes:
                                nodes.append({'id': target_id, 'label': target_id, 'x': None, 'y': None})
                                seen_nodes.add(target_id)
                            edges.append({
                                'id': f"{source_id}_{target_id}",
                                'source': source_id,
                                'target': target_id,
                                'label': item.type
                            })
                result_data = {'nodes': nodes, 'edges': edges}
            return render(request, 'dashboard/admin_queries.html', {
                'queries': queries,
                'result_json': json.dumps(result_data),
                'selected_query': query,
                'is_active_filter': is_active_filter,
                'created_by_filter': created_by_filter,
            })
        except AdminQuery.DoesNotExist:
            return render(request, 'dashboard/admin_queries.html', {
                'queries': queries,
                'error': 'Query not found.',
                'is_active_filter': is_active_filter,
                'created_by_filter': created_by_filter,
            })
        except Exception as e:
            logger.error("Error executing admin query: %s", str(e))
            return render(request, 'dashboard/admin_queries.html', {
                'queries': queries,
                'error': f'Error executing query: {str(e)}',
                'is_active_filter': is_active_filter,
                'created_by_filter': created_by_filter,
            })

    return render(request, 'dashboard/admin_queries.html', {
        'queries': queries,
        'is_active_filter': is_active_filter,
        'created_by_filter': created_by_filter,
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
    return redirect('dashboard:admin_queries')

def predefined_query_result(request, query_id):
    """Execute a predefined query and display the result."""
    logger.debug("Entering predefined_query_result view with query_id: %s", query_id)
    error = None
    result = None
    query_obj = get_predefined_query_by_id(query_id)

    if not query_obj:
        error = 'Query not found.'
        logger.warning("Query not found: %s", query_id)
        return render(request, 'dashboard/predefined_query_result.html', {
            'error': error,
            'query': None,
            'result_json': None
        })

    # Check if query is safe
    if not is_safe_query(query_obj['query']):
        logger.warning("Unsafe predefined query detected: %s", query_obj['query'])
        error = 'Unsafe query detected. Only MATCH and RETURN queries are allowed.'
        return render(request, 'dashboard/predefined_query_result.html', {
            'error': error,
            'query': query_obj,
            'result_json': None
        })

    try:
        with get_driver().session() as session:
            result = session.run(query_obj['query'])
            nodes = []
            edges = []
            seen_nodes = set()
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
        logger.error("Predefined query failed: %s", str(e))

    return render(request, 'dashboard/predefined_query_result.html', {
        'query': query_obj,
        'result_json': json.dumps(result) if result else None,
        'error': error
    })

def check_node_duplicate(request):
    """Check if a node name already exists."""
    logger.debug("Entering check_node_duplicate view with method: %s", request.method)
    node_name = request.GET.get('node_name', '').strip()
    existing_nodes = get_existing_nodes()
    exists = node_name in existing_nodes
    logger.debug("Node %s exists: %s", node_name, exists)
    return JsonResponse({'exists': exists})

def explore_layers(request):
    """Explore nodes up to a specified depth."""
    logger.debug("Entering explore_layers view with method: %s", request.method)
    error = None
    result = None

    if request.method == 'POST':
        node_name = request.POST.get('node_name', '').strip()
        depth = request.POST.get('depth', '').strip()
        logger.debug("Received node_name: %s, depth: %s", node_name, depth)

        if not node_name or not depth:
            error = 'Please enter both node name and depth.'
            logger.warning("Node name or depth missing")
        else:
            try:
                depth = int(depth)
                if depth < 1:
                    raise ValueError("Depth must be positive")
                query = (
                    f"MATCH (n:Node {{name: $node_name}})-[r*1..{depth}]->(m) "
                    "RETURN n, r, m"
                )
                with get_driver().session() as session:
                    result_data = session.run(query, node_name=node_name)
                    nodes = []
                    edges = []
                    seen_nodes = set()
                    for record in result_data:
                        start_node = record['n']
                        start_id = start_node['name'].replace(' ', '_')
                        if start_id not in seen_nodes:
                            nodes.append({'id': start_id, 'label': start_node['name'], 'x': None, 'y': None})
                            seen_nodes.add(start_id)
                        end_node = record['m']
                        end_id = end_node['name'].replace(' ', '_')
                        if end_id not in seen_nodes:
                            nodes.append({'id': end_id, 'label': end_node['name'], 'x': None, 'y': None})
                            seen_nodes.add(end_id)
                        for rel in record['r']:
                            source_id = rel.start_node['name'].replace(' ', '_')
                            target_id = rel.end_node['name'].replace(' ', '_')
                            edge_id = f"{source_id}_{target_id}"
                            if edge_id not in {edge['id'] for edge in edges}:
                                edges.append({'id': edge_id, 'source': source_id, 'target': target_id, 'label': 'R'})
                    result = {'nodes': nodes, 'edges': edges}
                    logger.debug("Explore layers result: %s", json.dumps(result, indent=2))
            except ValueError as e:
                error = f'Depth must be a positive number: {str(e)}'
                logger.error("Invalid depth: %s", str(e))
            except Exception as e:
                error = f'Error exploring layers: {str(e)}'
                logger.error("Explore layers failed: %s", str(e))

    return render(request, 'dashboard/explore_layers.html', {
        'result_json': json.dumps(result) if result else None,
        'error': error,
        'node_name': request.POST.get('node_name', '') if request.method == 'POST' else ''
    })

def predefined_queries(request):
    """Render the predefined queries page."""
    logger.debug("Entering predefined_queries view")
    predefined_queries = []
    try:
        predefined_queries = get_all_predefined_queries()
        logger.debug("Retrieved predefined queries: %s", predefined_queries)
    except Exception as e:
        logger.error("Error retrieving predefined queries: %s", str(e))

    return render(request, 'dashboard/predefined_queries.html', {
        'predefined_queries': predefined_queries
    })

def custom_404(request, exception=None):
    """Render custom 404 page."""
    logger.debug("Entering custom_404 view")
    return render(request, 'dashboard/404.html', status=404)