from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from bson import ObjectId
from .models import TestCase, TestStep, Section, SectionPermission, ChangeHistory
from .forms import TestCaseForm


def user_can_edit_sections(user):
    """Check if user can edit sections (admin or has permission)"""
    if user.role == 3:  # Admin
        return True
    try:
        permission = SectionPermission.objects.get(user_id=user.id)
        return permission.can_edit
    except SectionPermission.DoesNotExist:
        return False


def user_can_delete_sections(user):
    """Check if user can delete sections (admin or has permission)"""
    if user.role == 3:  # Admin
        return True
    try:
        permission = SectionPermission.objects.get(user_id=user.id)
        return permission.can_delete
    except SectionPermission.DoesNotExist:
        return False


def record_change(entity_type, entity_id, action, user_id, description=''):
    """Record a change in the change history"""
    try:
        ChangeHistory(
            entity_type=entity_type,
            entity_id=str(entity_id),
            action=action,
            user_id=user_id,
            description=description
        ).save()
    except Exception as e:
        # Don't fail the main operation if history recording fails
        print(f"Error recording change history: {str(e)}")


@login_required
def test_case_list(request):
    """List all test cases, optionally filtered by section or test case."""
    if not request.user.can_access_test_cases:
        messages.error(request, 'You do not have permission to access the Test Cases project.')
        return redirect('dashboard:home')
    # Get filter parameters
    section_filter = request.GET.get('section')
    test_case_filter = request.GET.get('test_case')
    sort_param = request.GET.get('sort', 'section')  # Default sort by section
    filter_param = request.GET.get('filter', 'all')  # Default filter: all
    
    # If a specific test case is selected, get it for detail view
    selected_test_case = None
    if test_case_filter:
        try:
            selected_test_case = TestCase.objects.get(id=ObjectId(test_case_filter), is_deleted=False)
        except (TestCase.DoesNotExist, Exception):
            pass
    
    # Query test cases
    test_cases_query = TestCase.objects(is_deleted=False)
    
    # If a test case is selected, don't show the list - only show detail
    if selected_test_case:
        # When showing detail, we still need test_cases for context, but filter by section
        if selected_test_case.section:
            test_cases_query = test_cases_query.filter(section=selected_test_case.section)
    elif section_filter:
        # If section is selected, show only that section's test cases
        try:
            section = Section.objects.get(id=ObjectId(section_filter))
            test_cases_query = test_cases_query.filter(section=section)
        except (Section.DoesNotExist, Exception):
            pass
    
    # Apply filter (only if not already filtered by section from tree selection)
    # Note: If section_filter is set, we already filtered by section above
    # So we only apply additional filters (type, priority) or override section filter if explicitly requested
    if filter_param == 'all':
        pass  # Show all (or what's already filtered by section)
    elif filter_param.startswith('section_'):
        # Filter by specific section (this overrides the tree section filter)
        try:
            filter_section_id = filter_param.replace('section_', '')
            filter_section = Section.objects.get(id=ObjectId(filter_section_id))
            # Override the section filter from tree
            test_cases_query = TestCase.objects(is_deleted=False).filter(section=filter_section)
        except (Section.DoesNotExist, Exception):
            pass
    elif filter_param.startswith('type_'):
        # Filter by type (applies on top of section filter if any)
        filter_type = filter_param.replace('type_', '')
        test_cases_query = test_cases_query.filter(type=filter_type)
    elif filter_param.startswith('priority_'):
        # Filter by priority (applies on top of section filter if any)
        filter_priority = filter_param.replace('priority_', '')
        test_cases_query = test_cases_query.filter(priority=filter_priority)
    
    # Apply sorting
    if sort_param == 'section':
        # Sort by section name, then by created date
        test_cases_list = list(test_cases_query)
        test_cases_list.sort(key=lambda tc: (
            tc.section.name if tc.section else '',
            tc.created_at
        ), reverse=True)
        test_cases = test_cases_list
    elif sort_param == 'title':
        test_cases = list(test_cases_query.order_by('title'))
    elif sort_param == 'date_newest':
        test_cases = list(test_cases_query.order_by('-created_at'))
    elif sort_param == 'date_oldest':
        test_cases = list(test_cases_query.order_by('created_at'))
    elif sort_param == 'type':
        test_cases = list(test_cases_query.order_by('type', '-created_at'))
    elif sort_param == 'priority':
        # Priority order: Critical, High, Medium, Low
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        test_cases_list = list(test_cases_query)
        test_cases_list.sort(key=lambda tc: (
            priority_order.get(tc.priority, 99),
            tc.created_at
        ))
        test_cases = test_cases_list
    else:
        test_cases = list(test_cases_query.order_by('-created_at'))
    
    # Build hierarchical tree structure from sections that have test cases
    all_sections = list(Section.objects().order_by('name'))
    
    # Build tree structure
    def build_section_tree(sections, parent=None):
        """Build hierarchical tree of sections"""
        tree = []
        for section in sections:
            # Check if this section belongs to the current parent level
            section_has_parent = section.parent is not None
            parent_is_none = parent is None
            
            # Match logic:
            # - If parent is None, include sections with no parent
            # - If parent is set, include sections where section.parent == parent
            if parent_is_none and not section_has_parent:
                # Root level section (no parent)
                # Get test cases for this section
                section_test_cases = list(TestCase.objects(section=section, is_deleted=False).order_by('id'))
                
                # Check if this section has any subsections in the database
                direct_subsections_count = Section.objects(parent=section).count()
                
                # Recursively build subsections
                subsections = build_section_tree(sections, parent=section)
                has_test_cases = len(section_test_cases) > 0
                has_subsections = len(subsections) > 0
                has_direct_subsections = direct_subsections_count > 0
                
                # ALWAYS include root sections - they should appear in the tree even if empty
                # This ensures newly created sections are visible
                tree.append({
                    'section': section,
                    'test_cases': section_test_cases,
                    'subsections': subsections,
                    'has_cases': has_test_cases or has_subsections or has_direct_subsections,
                })
            elif not parent_is_none and section_has_parent and str(section.parent.id) == str(parent.id):
                # Subsection (has parent matching current parent)
                # Get test cases for this section
                section_test_cases = list(TestCase.objects(section=section, is_deleted=False).order_by('id'))
                
                # Check if this section has any subsections in the database
                direct_subsections_count = Section.objects(parent=section).count()
                
                # Recursively build subsections
                subsections = build_section_tree(sections, parent=section)
                has_test_cases = len(section_test_cases) > 0
                has_subsections = len(subsections) > 0
                has_direct_subsections = direct_subsections_count > 0
                
                # ALWAYS include subsections - they should appear in the tree even if empty
                # This ensures newly created subsections are visible
                tree.append({
                    'section': section,
                    'test_cases': section_test_cases,
                    'subsections': subsections,
                    'has_cases': has_test_cases or has_subsections or has_direct_subsections,
                })
        return tree
    
    # Build tree starting from root sections (no parent)
    section_tree = build_section_tree(all_sections, parent=None)
    
    # Get sections that have test cases for filter dropdown
    sections_with_cases = []
    for section in all_sections:
        if TestCase.objects(section=section, is_deleted=False).count() > 0:
            sections_with_cases.append(section)
    
    # Count total sections and cases (only those that appear in tree)
    def count_sections_in_tree(tree):
        """Recursively count all sections in the tree"""
        count = 0
        for item in tree:
            count += 1  # Count this section
            count += count_sections_in_tree(item['subsections'])  # Count subsections
        return count
    
    total_sections = count_sections_in_tree(section_tree)
    total_cases = TestCase.objects(is_deleted=False).count()
    
    # Get steps for selected test case if one is selected
    selected_test_case_steps = None
    selected_test_case_history = None
    if selected_test_case:
        selected_test_case_steps = sorted(selected_test_case.steps, key=lambda x: x.step_number) if selected_test_case.steps else []
        # Get change history for selected test case
        selected_test_case_history = ChangeHistory.objects(
            entity_type='test_case',
            entity_id=str(selected_test_case.id)
        ).order_by('-timestamp')[:50]  # Limit to last 50 changes
    
    # Get selected section object if section is selected
    selected_section_obj = None
    if section_filter:
        try:
            selected_section_obj = Section.objects.get(id=ObjectId(section_filter))
        except (Section.DoesNotExist, Exception):
            pass
    
    # Get unique types and priorities for filter dropdown
    all_test_cases = TestCase.objects(is_deleted=False)
    unique_types = sorted(set(tc.type for tc in all_test_cases if tc.type))
    unique_priorities = sorted(set(tc.priority for tc in all_test_cases if tc.priority))
    
    context = {
        'test_cases': test_cases,
        'sections': sections_with_cases,
        'all_sections': all_sections,
        'unique_types': unique_types,
        'unique_priorities': unique_priorities,
        'selected_section': section_filter,
        'selected_section_obj': selected_section_obj,
        'selected_test_case': test_case_filter,
        'selected_test_case_obj': selected_test_case,
        'selected_test_case_steps': selected_test_case_steps,
        'selected_test_case_history': selected_test_case_history,
        'section_tree': section_tree,
        'total_sections': total_sections,
        'total_cases': total_cases,
        'current_sort': sort_param,
        'current_filter': filter_param,
        'user_can_edit': user_can_edit_sections(request.user),
        'user_can_delete': user_can_delete_sections(request.user),
    }
    return render(request, 'testcases/test_case_list.html', context)


@login_required
def test_case_add(request):
    """Add a new test case"""
    if request.method == 'POST':
        form = TestCaseForm(request.POST)
        if form.is_valid():
            # Get or create section
            section_id = form.cleaned_data.get('section')
            new_section_name = form.cleaned_data.get('new_section')
            
            if new_section_name:
                # Create new section (mongoengine doesn't have get_or_create)
                section_name = new_section_name.strip()
                try:
                    section = Section.objects.get(name=section_name)
                except Section.DoesNotExist:
                    section = Section(name=section_name)
                    section.save()
            elif section_id:
                try:
                    section = Section.objects.get(id=ObjectId(section_id))
                except (Section.DoesNotExist, Exception):
                    section = Section(name='Default', created_by_id=request.user.id)
                    section.save()
            else:
                section = Section(name='Default', created_by_id=request.user.id)
                section.save()
            
            # Create test case
            test_case = TestCase(
                title=form.cleaned_data['title'],
                section=section,
                type=form.cleaned_data['type'],
                priority=form.cleaned_data['priority'],
                estimate=form.cleaned_data.get('estimate', ''),
                automation_type=form.cleaned_data.get('automation_type', 'None'),
                labels=form.cleaned_data.get('labels', ''),
                description=form.cleaned_data.get('description', ''),
                preconditions=form.cleaned_data.get('preconditions', ''),
                template='Test Case (Steps)',  # Always set to this
                created_by_id=request.user.id,
                is_deleted=False
            )
            
            # Handle test steps - steps are required
            steps_data = request.POST.getlist('steps[]')
            expected_results = request.POST.getlist('expected_results[]')
            
            if not steps_data or not any(step.strip() for step in steps_data):
                form.add_error(None, "At least one test step with description is required.")
                context = {'form': form}
                return render(request, 'testcases/test_case_add.html', context)
            
            test_steps = []
            for idx, (step_desc, expected) in enumerate(zip(steps_data, expected_results), start=1):
                if step_desc.strip():  # Only create step if description is not empty
                    if not expected.strip():
                        form.add_error(None, f"Step {idx} requires an expected result.")
                        context = {'form': form}
                        return render(request, 'testcases/test_case_add.html', context)
                    test_steps.append(TestStep(
                        step_number=idx,
                        description=step_desc.strip(),
                        expected_result=expected.strip()
                    ))
            
            if not test_steps:
                form.add_error(None, "At least one test step with description and expected result is required.")
                context = {'form': form}
                return render(request, 'testcases/test_case_add.html', context)
            
            test_case.steps = test_steps
            test_case.save()
            
            # Record change history
            record_change('test_case', str(test_case.id), 'created', request.user.id, f'Created test case: {test_case.title}')
            
            messages.success(request, f'Test case "{test_case.title}" created successfully!')
            
            # Check if "Add & Next" was clicked
            if request.POST.get('add_and_next'):
                return redirect('testcases:test_case_add')
            return redirect('testcases:test_case_list')
    else:
        form = TestCaseForm()
    
    # Pre-select section if provided in query params
    initial_section = request.GET.get('section')
    if initial_section:
        form.fields['section'].initial = initial_section
    
    context = {
        'form': form,
    }
    return render(request, 'testcases/test_case_add.html', context)


@login_required
def test_case_detail(request, pk):
    """View test case details"""
    try:
        test_case = TestCase.objects.get(id=ObjectId(pk), is_deleted=False)
    except (TestCase.DoesNotExist, Exception):
        raise Http404("Test case not found")
    
    # Steps are embedded, so we can access them directly
    steps = sorted(test_case.steps, key=lambda x: x.step_number) if test_case.steps else []
    
    # Get change history for this test case
    change_history = ChangeHistory.objects(
        entity_type='test_case',
        entity_id=str(test_case.id)
    ).order_by('-timestamp')[:50]  # Limit to last 50 changes
    
    context = {
        'test_case': test_case,
        'steps': steps,
        'user_can_edit': user_can_edit_sections(request.user),
        'user_can_delete': user_can_delete_sections(request.user),
        'change_history': change_history,
    }
    return render(request, 'testcases/test_case_detail.html', context)


@login_required
def test_case_edit(request, pk):
    """Edit an existing test case"""
    # Check permissions
    if not user_can_edit_sections(request.user):
        messages.error(request, 'You do not have permission to edit test cases.')
        try:
            test_case = TestCase.objects.get(id=ObjectId(pk), is_deleted=False)
            return redirect('testcases:test_case_detail', pk=str(test_case.id))
        except (TestCase.DoesNotExist, Exception):
            return redirect('testcases:test_case_list')
    
    try:
        test_case = TestCase.objects.get(id=ObjectId(pk), is_deleted=False)
    except (TestCase.DoesNotExist, Exception):
        raise Http404("Test case not found")
    
    if request.method == 'POST':
        form = TestCaseForm(request.POST)
        if form.is_valid():
            # Get or create section
            section_id = form.cleaned_data.get('section')
            new_section_name = form.cleaned_data.get('new_section')
            
            if new_section_name:
                # Create new section (mongoengine doesn't have get_or_create)
                section_name = new_section_name.strip()
                try:
                    section = Section.objects.get(name=section_name)
                except Section.DoesNotExist:
                    section = Section(name=section_name, created_by_id=request.user.id)
                    section.save()
            elif section_id:
                try:
                    section = Section.objects.get(id=ObjectId(section_id))
                except (Section.DoesNotExist, Exception):
                    section = test_case.section
            else:
                section = test_case.section
            
            # Update test case
            test_case.title = form.cleaned_data['title']
            test_case.section = section
            test_case.type = form.cleaned_data['type']
            test_case.priority = form.cleaned_data['priority']
            test_case.estimate = form.cleaned_data.get('estimate', '')
            test_case.automation_type = form.cleaned_data.get('automation_type', 'None')
            test_case.labels = form.cleaned_data.get('labels', '')
            test_case.description = form.cleaned_data.get('description', '')
            test_case.preconditions = form.cleaned_data.get('preconditions', '')
            
            # Handle test steps - steps are required
            steps_data = request.POST.getlist('steps[]')
            expected_results = request.POST.getlist('expected_results[]')
            
            if not steps_data or not any(step.strip() for step in steps_data):
                form.add_error(None, "At least one test step with description is required.")
                existing_steps = sorted(test_case.steps, key=lambda x: x.step_number) if test_case.steps else []
                context = {
                    'form': form,
                    'test_case': test_case,
                    'existing_steps': existing_steps,
                }
                return render(request, 'testcases/test_case_edit.html', context)
            
            test_steps = []
            for idx, (step_desc, expected) in enumerate(zip(steps_data, expected_results), start=1):
                if step_desc.strip():
                    if not expected.strip():
                        form.add_error(None, f"Step {idx} requires an expected result.")
                        existing_steps = sorted(test_case.steps, key=lambda x: x.step_number) if test_case.steps else []
                        context = {
                            'form': form,
                            'test_case': test_case,
                            'existing_steps': existing_steps,
                        }
                        return render(request, 'testcases/test_case_edit.html', context)
                    test_steps.append(TestStep(
                        step_number=idx,
                        description=step_desc.strip(),
                        expected_result=expected.strip()
                    ))
            
            if not test_steps:
                form.add_error(None, "At least one test step with description and expected result is required.")
                existing_steps = sorted(test_case.steps, key=lambda x: x.step_number) if test_case.steps else []
                context = {
                    'form': form,
                    'test_case': test_case,
                    'existing_steps': existing_steps,
                }
                return render(request, 'testcases/test_case_edit.html', context)
            
            test_case.steps = test_steps
            test_case.updated_by_id = request.user.id
            test_case.save()
            
            # Record change history
            record_change('test_case', str(test_case.id), 'updated', request.user.id, f'Updated test case: {test_case.title}')
            
            messages.success(request, f'Test case "{test_case.title}" updated successfully!')
            return redirect('testcases:test_case_detail', pk=str(test_case.id))
    else:
        # Pre-populate form with existing data
        form = TestCaseForm(initial={
            'title': test_case.title,
            'section': str(test_case.section.id) if test_case.section else '',
            'type': test_case.type,
            'priority': test_case.priority,
            'estimate': test_case.estimate,
            'automation_type': test_case.automation_type,
            'labels': test_case.labels,
            'description': getattr(test_case, 'description', ''),
            'preconditions': test_case.preconditions,
        })
    
    existing_steps = sorted(test_case.steps, key=lambda x: x.step_number) if test_case.steps else []
    
    context = {
        'form': form,
        'test_case': test_case,
        'existing_steps': existing_steps,
    }
    return render(request, 'testcases/test_case_edit.html', context)


@login_required
@require_http_methods(["POST"])
def test_case_delete(request, pk):
    """Delete a test case (soft delete)"""
    # Check permissions
    if not user_can_delete_sections(request.user):
        messages.error(request, 'You do not have permission to delete test cases.')
        return redirect('testcases:test_case_list')
    
    try:
        test_case = TestCase.objects.get(id=ObjectId(pk), is_deleted=False)
        test_case.is_deleted = True
        test_case.updated_by_id = request.user.id
        test_case.save()
        
        # Record change history
        record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title}')
        
        messages.success(request, f'Test case "{test_case.title}" deleted successfully!')
    except (TestCase.DoesNotExist, Exception):
        messages.error(request, 'Test case not found.')
    
    return redirect('testcases:test_case_list')


@login_required
@require_http_methods(["POST"])
def section_add(request):
    """Add a new root section (no parent)"""
    section_name = request.POST.get('section_name', '').strip()
    section_description = request.POST.get('section_description', '').strip()
    
    if section_name:
        try:
            # Check if section already exists at root level (no parent)
            # Try both methods to check for existing root sections
            try:
                existing = Section.objects.get(name=section_name, parent__exists=False)
                messages.warning(request, f'Section "{section_name}" already exists.')
            except Section.DoesNotExist:
                try:
                    # Also try checking with parent=None
                    existing = Section.objects.get(name=section_name, parent=None)
                    messages.warning(request, f'Section "{section_name}" already exists.')
                except Section.DoesNotExist:
                    # Create new root section
                    try:
                        section = Section(
                            name=section_name,
                            parent=None,
                            description=section_description or '',
                            created_by_id=request.user.id
                        )
                        # Validate before saving
                        section.clean()
                        section.save()
                        
                        # Record change history
                        record_change('section', str(section.id), 'created', request.user.id, f'Created section: {section_name}')
                        
                        # Verify it was saved
                        saved_section = Section.objects.get(id=section.id)
                        messages.success(request, f'Section "{section_name}" created successfully!')
                    except Exception as e:
                        import traceback
                        error_details = traceback.format_exc()
                        messages.error(request, f'Error creating section: {str(e)}')
                        # Log the full error for debugging
                        print(f"Error creating section: {error_details}")
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
    else:
        messages.error(request, 'Section name is required.')
    
    # Redirect back to test case list
    return redirect('testcases:test_case_list')


@login_required
def section_add_subsection(request, section_id):
    """Add a subsection to an existing section"""
    if request.method == 'POST':
        subsection_name = request.POST.get('subsection_name', '').strip()
        subsection_description = request.POST.get('subsection_description', '').strip()
        
        if subsection_name:
            try:
                parent_section = Section.objects.get(id=ObjectId(section_id))
                # Check if subsection already exists under this parent
                try:
                    existing = Section.objects.get(name=subsection_name, parent=parent_section)
                    messages.warning(request, f'Subsection "{subsection_name}" already exists under "{parent_section.name}".')
                except Section.DoesNotExist:
                    # Create new subsection
                    try:
                        subsection = Section(
                            name=subsection_name,
                            parent=parent_section,
                            description=subsection_description if subsection_description else '',
                            created_by_id=request.user.id
                        )
                        # Validate before saving
                        subsection.clean()
                        subsection.save()
                        
                        # Record change history
                        record_change('section', str(subsection.id), 'created', request.user.id, f'Created subsection: {subsection_name} under {parent_section.name}')
                        
                        # Verify it was saved
                        saved_subsection = Section.objects.get(id=subsection.id)
                        messages.success(request, f'Subsection "{subsection_name}" created successfully under "{parent_section.name}"!')
                    except Exception as e:
                        import traceback
                        error_details = traceback.format_exc()
                        messages.error(request, f'Error creating subsection: {str(e)}')
                        # Log the full error for debugging
                        print(f"Error creating subsection: {error_details}")
            except (Section.DoesNotExist, Exception) as e:
                messages.error(request, f'Error: {str(e)}')
        else:
            messages.error(request, 'Subsection name is required.')
        
        # Redirect with query parameter
        return redirect(f"{reverse('testcases:test_case_list')}?section={section_id}")
    else:
        # GET request - redirect back
        return redirect(f"{reverse('testcases:test_case_list')}?section={section_id}")


@login_required
def section_manage(request):
    """Manage sections - list, edit, and delete sections"""
    # Handle permission updates (admin only) - check before other POST handlers
    if request.method == 'POST' and 'update_permissions' in request.POST:
        if request.user.role != 3:  # Only admins
            messages.error(request, 'Only administrators can manage permissions.')
            return redirect('testcases:section_manage')
        
        user_id = request.POST.get('user_id')
        can_edit = request.POST.get('can_edit') == 'on'
        can_delete = request.POST.get('can_delete') == 'on'
        
        if user_id:
            try:
                # MongoEngine doesn't have get_or_create, so we need to do it manually
                try:
                    permission = SectionPermission.objects.get(user_id=int(user_id))
                except SectionPermission.DoesNotExist:
                    permission = SectionPermission(user_id=int(user_id))
                
                permission.can_edit = can_edit
                permission.can_delete = can_delete
                permission.save()
                messages.success(request, f'Permissions updated successfully.')
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                messages.error(request, f'Error updating permissions: {str(e)}')
                print(f"Error updating permissions: {error_details}")
        return redirect('testcases:section_manage')
    
    # Handle bulk delete of sections
    if request.method == 'POST' and 'delete_sections' in request.POST:
        # Check permissions
        if not user_can_delete_sections(request.user):
            messages.error(request, 'You do not have permission to delete sections.')
            return redirect('testcases:section_manage')
        section_ids = request.POST.getlist('section_ids')
        deleted_count = 0
        
        # Helper function to recursively delete subsections
        def delete_subsection_recursive(subsection):
            # Delete test cases in subsection (soft delete)
            subsection_test_cases = TestCase.objects(section=subsection, is_deleted=False)
            for test_case in subsection_test_cases:
                test_case.is_deleted = True
                test_case.updated_by_id = request.user.id
                test_case.save()
                # Record change history
                record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title} (via bulk section deletion)')
            
            # Recursively delete child subsections
            child_subsections = Section.objects(parent=subsection)
            for child in child_subsections:
                delete_subsection_recursive(child)
            
            # Record change history before deleting subsection
            record_change('section', str(subsection.id), 'deleted', request.user.id, f'Deleted subsection: {subsection.name} (via bulk deletion)')
            # Delete the subsection itself
            subsection.delete()
        
        for section_id in section_ids:
            try:
                section = Section.objects.get(id=ObjectId(section_id))
                section_name = section.name
                
                # Delete all test cases in this section (soft delete)
                test_cases = TestCase.objects(section=section, is_deleted=False)
                for test_case in test_cases:
                    test_case.is_deleted = True
                    test_case.updated_by_id = request.user.id
                    test_case.save()
                    # Record change history
                    record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title} (via bulk section deletion)')
                
                # Delete all subsections recursively
                subsections = Section.objects(parent=section)
                for subsection in subsections:
                    delete_subsection_recursive(subsection)
                
                # Record change history before deleting section
                record_change('section', str(section.id), 'deleted', request.user.id, f'Deleted section: {section_name} (via bulk deletion)')
                # Delete the section itself
                section.delete()
                deleted_count += 1
            except (Section.DoesNotExist, Exception) as e:
                pass
        
        if deleted_count > 0:
            messages.success(request, f'Successfully deleted {deleted_count} section(s) and all their test cases and subsections.')
        else:
            messages.warning(request, 'No sections were deleted.')
        return redirect('testcases:section_manage')
    
    # Handle bulk delete of test cases
    if request.method == 'POST' and 'delete_test_cases' in request.POST:
        test_case_ids = request.POST.getlist('test_case_ids')
        deleted_count = 0
        for test_case_id in test_case_ids:
            try:
                test_case = TestCase.objects.get(id=ObjectId(test_case_id), is_deleted=False)
                test_case.is_deleted = True
                test_case.updated_by_id = request.user.id
                test_case.save()
                # Record change history
                record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title} (via bulk deletion)')
                deleted_count += 1
            except (TestCase.DoesNotExist, Exception):
                pass
        
        if deleted_count > 0:
            messages.success(request, f'Successfully deleted {deleted_count} test case(s).')
        else:
            messages.warning(request, 'No test cases were deleted.')
        return redirect('testcases:section_manage')
    
    # Get all sections with their hierarchy info
    all_sections = list(Section.objects().order_by('name'))
    
    # Build section data with counts and test cases
    sections_data = []
    all_test_cases = []
    
    for section in all_sections:
        # Get test cases in this section
        test_cases = list(TestCase.objects(section=section, is_deleted=False).order_by('-created_at'))
        
        # Count test cases in this section
        test_case_count = len(test_cases)
        
        # Count subsections
        subsection_count = Section.objects(parent=section).count()
        
        sections_data.append({
            'section': section,
            'test_case_count': test_case_count,
            'subsection_count': subsection_count,
            'parent_name': section.parent.name if section.parent else None,
            'test_cases': test_cases,  # Include test cases for display
        })
        
        # Add to all test cases list
        all_test_cases.extend(test_cases)
    
    # Get all users for permission management (admin only)
    # Only load this data if user is admin to prevent unnecessary queries
    all_users = []
    permissions_data = []
    is_admin = request.user.role == 3
    
    if is_admin:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        all_users = list(User.objects.filter(is_active=True).order_by('username'))
        
        # Get permissions for all users (only for admins)
        for user in all_users:
            try:
                permission = SectionPermission.objects.get(user_id=user.id)
                permissions_data.append({
                    'user': user,
                    'permission': permission,
                    'can_edit': permission.can_edit,
                    'can_delete': permission.can_delete,
                })
            except SectionPermission.DoesNotExist:
                permissions_data.append({
                    'user': user,
                    'permission': None,
                    'can_edit': False,
                    'can_delete': False,
                })
    
    context = {
        'sections': sections_data,
        'all_test_cases': all_test_cases,
        'all_users': all_users,  # Empty list for non-admins
        'permissions_data': permissions_data,  # Empty list for non-admins
        'user_can_edit': user_can_edit_sections(request.user),
        'user_can_delete': user_can_delete_sections(request.user),
        'is_admin': is_admin,  # Explicitly set for clarity
    }
    return render(request, 'testcases/section_manage.html', context)


@login_required
def section_edit(request, section_id):
    """Edit a section"""
    # Check permissions
    if not user_can_edit_sections(request.user):
        messages.error(request, 'You do not have permission to edit sections.')
        return redirect('testcases:section_manage')
    
    try:
        section = Section.objects.get(id=ObjectId(section_id))
    except (Section.DoesNotExist, Exception):
        messages.error(request, 'Section not found.')
        return redirect('testcases:section_manage')
    
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        
        if name:
            # Check if name already exists (excluding current section)
            try:
                existing = Section.objects.get(name=name, parent=section.parent)
                if str(existing.id) != str(section.id):
                    messages.error(request, f'A section with name "{name}" already exists in this parent.')
                    return redirect('testcases:section_edit', section_id=section_id)
            except Section.DoesNotExist:
                pass
            
            section.name = name
            section.description = description if description else ''
            section.updated_by_id = request.user.id
            section.save()
            
            # Record change history
            record_change('section', str(section.id), 'updated', request.user.id, f'Updated section: {section.name}')
            
            messages.success(request, f'Section "{section.name}" updated successfully!')
            return redirect('testcases:section_manage')
        else:
            messages.error(request, 'Section name is required.')
    
    # Get all sections for parent selection (excluding current section and its descendants)
    available_parents = []
    for s in Section.objects().order_by('name'):
        if str(s.id) != str(section.id) and (not section.parent or str(s.id) != str(section.parent.id)):
            # Check if section is a descendant of current section (to prevent circular references)
            is_descendant = False
            current = section.parent
            while current:
                if str(current.id) == str(s.id):
                    is_descendant = True
                    break
                current = current.parent
            
            if not is_descendant:
                available_parents.append(s)
    
    context = {
        'section': section,
        'available_parents': available_parents,
    }
    return render(request, 'testcases/section_edit.html', context)


@login_required
@require_http_methods(["POST"])
def section_delete(request, section_id):
    """Delete a section and all its test cases and subsections"""
    # Check permissions
    if not user_can_delete_sections(request.user):
        messages.error(request, 'You do not have permission to delete sections.')
        return redirect('testcases:section_manage')
    
    try:
        section = Section.objects.get(id=ObjectId(section_id))
    except (Section.DoesNotExist, Exception):
        messages.error(request, 'Section not found.')
        return redirect('testcases:section_manage')
    
    section_name = section.name
    
    # Delete all test cases in this section (soft delete)
    test_cases = TestCase.objects(section=section, is_deleted=False)
    test_case_count = test_cases.count()
    for test_case in test_cases:
        test_case.is_deleted = True
        test_case.updated_by_id = request.user.id
        test_case.save()
        # Record change history
        record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title} (via section deletion)')
    
    # Delete all subsections recursively
    def delete_subsection_recursive(subsection):
        # Delete test cases in subsection
        subsection_test_cases = TestCase.objects(section=subsection, is_deleted=False)
        for test_case in subsection_test_cases:
            test_case.is_deleted = True
            test_case.updated_by_id = request.user.id
            test_case.save()
            # Record change history
            record_change('test_case', str(test_case.id), 'deleted', request.user.id, f'Deleted test case: {test_case.title} (via section deletion)')
        
        # Recursively delete child subsections
        child_subsections = Section.objects(parent=subsection)
        for child in child_subsections:
            delete_subsection_recursive(child)
        
        # Record change history before deleting subsection
        record_change('section', str(subsection.id), 'deleted', request.user.id, f'Deleted subsection: {subsection.name}')
        # Delete the subsection itself
        subsection.delete()
    
    subsections = Section.objects(parent=section)
    subsection_count = subsections.count()
    for subsection in subsections:
        delete_subsection_recursive(subsection)
    
    # Record change history before deleting section
    record_change('section', str(section.id), 'deleted', request.user.id, f'Deleted section: {section_name}')
    # Delete the section itself
    section.delete()
    
    messages.success(request, f'Section "{section_name}" and all its {test_case_count} test case(s) and {subsection_count} subsection(s) deleted successfully!')
    return redirect('testcases:section_manage')
