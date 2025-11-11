from django import forms
from .models import TestCase, Section


class TestCaseForm(forms.Form):
    """Form for creating/editing test cases"""
    
    title = forms.CharField(
        max_length=500,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'required': True,
        })
    )
    
    # Section can be existing or new
    section = forms.ChoiceField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control',
        })
    )
    
    new_section = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new section name',
        })
    )
    
    type = forms.ChoiceField(
        choices=TestCase.TYPE_CHOICES,
        initial='Other',
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': True,
        })
    )
    
    priority = forms.ChoiceField(
        choices=TestCase.PRIORITY_CHOICES,
        initial='Medium',
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': True,
        })
    )
    
    estimate = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
        })
    )
    
    automation_type = forms.ChoiceField(
        choices=TestCase.AUTOMATION_TYPE_CHOICES,
        initial='None',
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control',
        })
    )
    
    labels = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Start typing',
        })
    )
    
    preconditions = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 5,
            'placeholder': 'The preconditions of this test case. Reference other test cases with [C#] (e.g. [C17]).',
            'required': True,
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate section choices
        sections = Section.objects().order_by('name')
        section_choices = [('', '-- Create New Section --')]
        section_choices.extend([(str(section.id), section.name) for section in sections])
        self.fields['section'].choices = section_choices

    def clean(self):
        cleaned_data = super().clean()
        section = cleaned_data.get('section')
        new_section = cleaned_data.get('new_section')
        preconditions = cleaned_data.get('preconditions')
        
        # Either section or new_section must be provided
        if not section and not new_section:
            raise forms.ValidationError("Please select an existing section or enter a new section name.")
        
        # Preconditions is required
        if not preconditions or not preconditions.strip():
            raise forms.ValidationError("Preconditions field is required.")
        
        return cleaned_data
