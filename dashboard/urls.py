from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='home'),
    path('get-existing-nodes/', views.get_existing_nodes_view, name='get_existing_nodes'),
    path('add-nodes/', views.add_nodes, name='add_nodes'),
    path('define-relations/', views.define_relations, name='define_relations'),
    path('confirm-relationships/', views.confirm_relationships, name='confirm_relationships'),  # مسیر جدید
    path('manual-queries/', views.manual_queries, name='manual_queries'),
    path('graph-view/', views.graph_view, name='graph_view'),
    path('admin-queries/', views.admin_queries, name='admin_queries'),
    path('delete-predefined-query/<str:query_id>/', views.delete_predefined_query, name='delete_predefined_query'),
    path('predefined-query-result/<str:query_id>/', views.predefined_query_result, name='predefined_query_result'),
    path('check-node-duplicate/', views.check_node_duplicate, name='check_node_duplicate'),
    path('explore-layers/', views.explore_layers, name='explore_layers'),
    path('predefined-queries/', views.predefined_queries, name='predefined_queries'),
    path('export-manual-query/', views.export_manual_query, name='export_manual_query'),
    path('test-impact-analysis/', views.test_impact_analysis, name='test_impact_analysis'),
    path('test-analysis/', views.test_analysis_dashboard, name='test_analysis'),
    path('api/test-coverage/', views.get_test_coverage, name='test_coverage'),
    path('api/test-results/', views.get_test_results, name='test_results'),
    path('api/impact-analysis/', views.get_impact_analysis, name='impact_analysis'),
    path('manage_nodes/', views.manage_nodes, name='manage_nodes'),  # New URL pattern
]