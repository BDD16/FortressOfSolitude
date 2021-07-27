"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

from django.views.generic import UpdateView as BaseUpdateView


class UpdateView(BaseUpdateView):
    template_name_suffix = '_form_update'
