from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from bson import ObjectId
from .models import TestCase, TestStep, Section
from .forms import TestCaseForm


@login_required
def test_case_list(request):
    """Display list of test cases"""
    # Get filter parameters
    section_filter = request.GET.get('section')
    test_case_filter = request.GET.get('test_case')
    
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
                
                # Include section if it has test cases, subsections in tree, or direct subsections in DB
                # This ensures sections with subsections (even empty ones) are shown
                if has_test_cases or has_subsections or has_direct_subsections:
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
    if selected_test_case:
        selected_test_case_steps = sorted(selected_test_case.steps, key=lambda x: x.step_number) if selected_test_case.steps else []
    
    # Get selected section object if section is selected
    selected_section_obj = None
    if section_filter:
        try:
            selected_section_obj = Section.objects.get(id=ObjectId(section_filter))
        except (Section.DoesNotExist, Exception):
            pass
    
    context = {
        'test_cases': test_cases,
        'sections': sections_with_cases,
        'selected_section': section_filter,
        'selected_section_obj': selected_section_obj,
        'selected_test_case': test_case_filter,
        'selected_test_case_obj': selected_test_case,
        'selected_test_case_steps': selected_test_case_steps,
        'section_tree': section_tree,
        'total_sections': total_sections,
        'total_cases': total_cases,
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
                    section = Section(name='Default')
                    section.save()
            else:
                section = Section(name='Default')
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
    
    context = {
        'test_case': test_case,
        'steps': steps,
    }
    return render(request, 'testcases/test_case_detail.html', context)


@login_required
def test_case_edit(request, pk):
    """Edit an existing test case"""
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
                    section = Section(name=section_name)
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
            test_case.save()
            
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
    try:
        test_case = TestCase.objects.get(id=ObjectId(pk), is_deleted=False)
        test_case.is_deleted = True
        test_case.save()
        messages.success(request, f'Test case "{test_case.title}" deleted successfully!')
    except (TestCase.DoesNotExist, Exception):
        messages.error(request, 'Test case not found.')
    
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
                            description=subsection_description if subsection_description else ''
                        )
                        # Validate before saving
                        subsection.clean()
                        subsection.save()
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
    # Handle bulk delete of sections
    if request.method == 'POST' and 'delete_sections' in request.POST:
        section_ids = request.POST.getlist('section_ids')
        deleted_count = 0
        
        # Helper function to recursively delete subsections
        def delete_subsection_recursive(subsection):
            # Delete test cases in subsection (soft delete)
            subsection_test_cases = TestCase.objects(section=subsection, is_deleted=False)
            for test_case in subsection_test_cases:
                test_case.is_deleted = True
                test_case.save()
            
            # Recursively delete child subsections
            child_subsections = Section.objects(parent=subsection)
            for child in child_subsections:
                delete_subsection_recursive(child)
            
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
                    test_case.save()
                
                # Delete all subsections recursively
                subsections = Section.objects(parent=section)
                for subsection in subsections:
                    delete_subsection_recursive(subsection)
                
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
                test_case.save()
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
    
    context = {
        'sections': sections_data,
        'all_test_cases': all_test_cases,
    }
    return render(request, 'testcases/section_manage.html', context)


@login_required
def section_edit(request, section_id):
    """Edit a section"""
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
            section.save()
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
        test_case.save()
    
    # Delete all subsections recursively
    def delete_subsection_recursive(subsection):
        # Delete test cases in subsection
        subsection_test_cases = TestCase.objects(section=subsection, is_deleted=False)
        for test_case in subsection_test_cases:
            test_case.is_deleted = True
            test_case.save()
        
        # Recursively delete child subsections
        child_subsections = Section.objects(parent=subsection)
        for child in child_subsections:
            delete_subsection_recursive(child)
        
        # Delete the subsection itself
        subsection.delete()
    
    subsections = Section.objects(parent=section)
    subsection_count = subsections.count()
    for subsection in subsections:
        delete_subsection_recursive(subsection)
    
    # Delete the section itself
    section.delete()
    
    messages.success(request, f'Section "{section_name}" and all its {test_case_count} test case(s) and {subsection_count} subsection(s) deleted successfully!')
    return redirect('testcases:section_manage')
