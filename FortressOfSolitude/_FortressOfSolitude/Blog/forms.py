'''
DBA 1337_TECH, AUSTIN TEXAS © MAY 2020
Proof of Concept code, No liabilities or warranties expressed or implied.
'''

from django import forms
from django.contrib.auth import get_user

from .models import Post, SecureDataAtRestPost
from _FortressOfSolitude.organizer.models import SecureNote
from _FortressOfSolitude.NeutrinoKey.models import DEK, KEK


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        exclude = ('author',)

    def clean_slug(self):
        return self.cleaned_data['slug'].lower()

    def save(self, request, commit=True):
        post = super().save(commit=False)
        if not post.pk:
            post.author = get_user(request)
        if commit:
            post.save()
            self.save_m2m()
        return post


class SecurePostForm(forms.ModelForm):
    class Meta:
        model = SecureDataAtRestPost
        exclude = ('author',)

    def clean_slug(self):
        return self.cleaned_data['slug'].lower()

    def save(self, request, commit=True):
        post = super().save(commit=False)
        if not post.pk:
            post.author = get_user(request)
        if commit:
            print("PK" + str(self.instance.pk))
            if self.instance.pk != None:
                x = self.instance.pk
                print("about to edit the secure note")
                post = post.__class__.objects._encrypt_update_Secure_Note(password=request.user.password,
                                                                          secure_text=post.secure_text, postobj=post,
                                                                          request=request)
                print("We just Edited the Secure Note")
            else:
                post = post.__class__.objects._encrypt_Secure_Note(password=request.user.password,
                                                                   secure_text=post.secure_text, postobj=post,
                                                                   request=request)
        return post
