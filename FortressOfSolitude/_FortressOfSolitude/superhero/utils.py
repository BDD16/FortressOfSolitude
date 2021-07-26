"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

from django.http import (
    HttpResponseRedirect)
from django.shortcuts import (
    render)
from django.views.generic import View


class RegisterMixin:

    def post(self, request):
        bound_form = self.form_class(request.POST)
        print(bound_form.is_valid())
        if bound_form.is_valid():
            user = self.model(
                email=email,
                is_active=True,
                is_staff=is_staff,
                is_superuser=is_superuser,
                **kwargs)
            user.set_password(password)
            user.save(using='superHeros')
            user.user_permission.add('Blog.view_post')
            user.user_permission.add('Blog.add_post')
            user.user_permission.add('organizer.view_tasking')
            user.user_permission.add('organizer.add_tag')
            user.user_permission.add('organizer.add_tasking')
            user.user_permission.add('organizer.add_blog_post')
            print(self.get_success_url())
            return HttpResponseRedirect(
                self.get_success_url())

    def form_valid(self, form):
        self.object = form.save(form)
        print(self.object)
        return HttpResponseRedirect(
            self.get_success_url())


class CreateView(View):
    form_class = None
    template_name = ''

    def get(self, request):
        return render(
            request,
            self.template_name,
            {'form': self.form_class()})

    '''
    def post(self, request):
        bound_form = self.form_class(request.POST)
        if bound_form.is_valid():
            new_object = bound_form.save()
            return HttpResponseRedirect(
                self.get_success_url())
        else:
            return render(
                request,
                self.template_name,
                {'form': bound_form})
     '''
