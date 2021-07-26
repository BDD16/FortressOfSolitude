"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

from django import forms


class DownloadFileForm(forms.Form):
    url = forms.CharField(max_length=32)
