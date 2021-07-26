"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

from django.conf import settings
from django.contrib.auth import get_user
from django.shortcuts import redirect


def custom_login_required(view):
    # view argument must be a function

    def new_view(request, *args, **kwargs):
        # View argument must be a function
        user = get_user(request)
        if user.is_authenticated():
            return view(request, *args, **kwargs)
        else:
            url = '{}?next={}'.format(settings.LOGIN_URL, request.path)
            return redirect(url)

    # TODO: ADD IN ZERO KNOWLEDGE AUTHENTICATION_WZK Implementation
    # My Idea to make this authentication work is using an && between django's
    # Built in authentication and my own ZKA_wzk implementation.  That way it
    # would take both to fail catastrophically in order for a user to be compromised
