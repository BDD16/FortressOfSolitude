"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

from django.conf.urls import url
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import AuthenticationForm
from django.views.generic import RedirectView

# TODO: Create a RegisterCreate View

urlpatterns = [
    url(r'^$', RedirectView.as_view(pattern_name='dj-auth:login', permanent=False)),
    url(r'^logout/$', auth_views.LogoutView.as_view(template_name='superhero/logged_out.html',
                                                    extra_context={'form': AuthenticationForm}),
        name='logout'),
    url(r'^login/$', auth_views.LoginView.as_view(template_name='superhero/login.html'), name='login'),
    # url(r'^register/$', RegisterCreate.as_view(), name='register_create'),

]
