from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('add-nodes/', views.add_nodes, name='add_nodes'),
    path('relationship-option/', views.relationship_option, name='relationship_option'),
    path('input-existing-nodes/', views.input_existing_nodes, name='input_existing_nodes'),
    path('define-relations-with-existing-nodes/', views.define_relations_with_existing_nodes, name='define_relations_with_existing_nodes'),
    path('define-new-node-relations/', views.define_new_node_relations, name='define_new_node_relations'),
    path('confirm-relations/', views.confirm_relations, name='confirm_relations'),
    path('manual-query/', views.manual_query, name='manual_query'),
    path('admin-queries/', views.admin_queries, name='admin_queries'),
    path('delete-predefined-query/<str:query_id>/', views.delete_predefined_query, name='delete_predefined_query'),
    path('predefined-query-result/<str:query_id>/', views.predefined_query_result, name='predefined_query_result'),
    path('check-node-duplicate/', views.check_node_duplicate, name='check_node_duplicate'),
    path('select-relationships/', views.select_relationships, name='select_relationships'),
    path('confirm-relationships/', views.confirm_relationships, name='confirm_relationships'),
    path('explore-layers/', views.explore_layers, name='explore_layers'),
]