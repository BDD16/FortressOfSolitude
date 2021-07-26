"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""
"""
_FortressOfSolitude URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/

Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

# Uncomment next two lines to enable admin:
from django.conf.urls import include, url
from django.contrib import admin
from django.urls import path
from _FortressOfSolitude.Blog.views import greeting
from _FortressOfSolitude.organizer.views import homepage, tag_detail
from _FortressOfSolitude.organizer import urls as organizer_urls
from _FortressOfSolitude.Blog import urls as blog_urls
from _FortressOfSolitude.Blog.views import PostList
from _FortressOfSolitude.superhero import urls as superhero_urls


urlpatterns = [
    # Uncomment the next line to enable the admin:
    path('admin/', admin.site.urls),
    url(r'^', include(organizer_urls)),
    url(r'^$', PostList.as_view()),
    url(r'^superhero/', include((superhero_urls, 'superhero'), namespace='dj-auth')),
    url(r'^blog/', include(blog_urls)),
    ]