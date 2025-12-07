from django.urls import path, re_path
from . import views

app_name = 'testcases'

urlpatterns = [
    # Project routes
    path('', views.project_dashboard, name='project_dashboard'),
    path('projects/', views.project_list, name='project_list'),
    path('projects/create/', views.project_create, name='project_create'),
    path('projects/<str:project_id>/edit/', views.project_edit, name='project_edit'),
    path('projects/<str:project_id>/delete/', views.project_delete, name='project_delete'),
    
    # Test run routes (with project) - MUST come before test_case_list to avoid URL conflicts
    # Specific routes first (with actions)
    path('projects/<str:project_id>/runs/add/', views.test_run_add, name='test_run_add'),
    path('projects/<str:project_id>/runs/select-cases/', views.test_run_select_cases, name='test_run_select_cases'),
    # Test run detail routes with test_run_id (must be valid ObjectId format - 24 hex chars)
    re_path(r'^projects/(?P<project_id>[^/]+)/runs/(?P<test_run_id>[0-9a-fA-F]{24})/test-case/(?P<test_case_id>[^/]+)/details/$', views.test_run_get_test_case_details, name='test_run_get_test_case_details'),
    re_path(r'^projects/(?P<project_id>[^/]+)/runs/(?P<test_run_id>[0-9a-fA-F]{24})/update-result/$', views.test_run_update_result, name='test_run_update_result'),
    re_path(r'^projects/(?P<project_id>[^/]+)/runs/(?P<test_run_id>[0-9a-fA-F]{24})/edit/$', views.test_run_edit, name='test_run_edit'),
    re_path(r'^projects/(?P<project_id>[^/]+)/runs/(?P<test_run_id>[0-9a-fA-F]{24})/delete/$', views.test_run_delete, name='test_run_delete'),
    re_path(r'^projects/(?P<project_id>[^/]+)/runs/(?P<test_run_id>[0-9a-fA-F]{24})/$', views.test_run_detail, name='test_run_detail'),
    # General test runs list (must be last)
    path('projects/<str:project_id>/runs/', views.test_run_list, name='test_run_list'),
    
    # Section routes (with project) - MUST come before test_case_list to avoid URL conflicts
    path('projects/<str:project_id>/sections/<str:section_id>/delete/', views.section_delete, name='section_delete'),
    path('projects/<str:project_id>/sections/<str:section_id>/edit/', views.section_edit, name='section_edit'),
    path('projects/<str:project_id>/section/<str:section_id>/add-subsection/', views.section_add_subsection, name='section_add_subsection'),
    path('projects/<str:project_id>/sections/manage/', views.section_manage, name='section_manage'),
    path('projects/<str:project_id>/sections/add/', views.section_add, name='section_add'),
    
    # Test case routes (with project)
    path('projects/<str:project_id>/export/', views.test_case_export, name='test_case_export'),
    path('projects/<str:project_id>/import/', views.test_case_import, name='test_case_import'),
    path('projects/<str:project_id>/add/', views.test_case_add, name='test_case_add'),
    
    # Test case detail routes (with project) - MUST come before test_case_list to avoid URL conflicts
    path('projects/<str:project_id>/<str:pk>/delete/', views.test_case_delete, name='test_case_delete'),
    path('projects/<str:project_id>/<str:pk>/edit/', views.test_case_edit, name='test_case_edit'),
    path('projects/<str:project_id>/<str:pk>/', views.test_case_detail, name='test_case_detail'),
    
    # Test case list route - MUST be last as it's the most general pattern
    path('projects/<str:project_id>/', views.test_case_list, name='test_case_list'),
]

