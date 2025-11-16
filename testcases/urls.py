from django.urls import path
from . import views

app_name = 'testcases'

urlpatterns = [
    path('', views.test_case_list, name='test_case_list'),
    path('add/', views.test_case_add, name='test_case_add'),
    path('sections/add/', views.section_add, name='section_add'),
    path('sections/manage/', views.section_manage, name='section_manage'),
    path('sections/<str:section_id>/edit/', views.section_edit, name='section_edit'),
    path('sections/<str:section_id>/delete/', views.section_delete, name='section_delete'),
    path('section/<str:section_id>/add-subsection/', views.section_add_subsection, name='section_add_subsection'),
    path('<str:pk>/', views.test_case_detail, name='test_case_detail'),
    path('<str:pk>/edit/', views.test_case_edit, name='test_case_edit'),
    path('<str:pk>/delete/', views.test_case_delete, name='test_case_delete'),
]

