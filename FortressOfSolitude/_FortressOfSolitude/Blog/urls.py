"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""


from django.conf.urls import url

from .views import ( PostCreate,
    PostDelete, PostDetail, PostList, PostUpdate, PostArchiveYear, PostArchiveMonth, SecurePostList, SecurePostDetail,
                     SecurePostCreate, SecurePostUpdate, SecurePostDelete, SecurePostArchiveYear,
                     SecurePostArchiveMonth)

urlpatterns = [
    url(r'^Securelist/$',
        SecurePostList.as_view(),
        name='blog_securepost_list'),
    url(r'^$',
        PostList.as_view(),
        name='blog_post_list'),
    url(r'^Securecreate/$',
        SecurePostCreate.as_view(),
        name='blog_securepost_create'),
    url(r'^create/$',
        PostCreate.as_view(),
        name='blog_post_create'),
    url(r'^(?P<year>\d{4})/$',
        PostArchiveYear.as_view(),
        name='blog_post_archive_year'),
    url(r'^(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/$',
        PostArchiveMonth.as_view(),
        name='blog_post_archive_month'),
    url(r'^SecureNote/(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/$',
        SecurePostDetail.as_view(),
        name='blog_securepost_detail'),
    url(r'^SecureNote/'
        r'(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/'
        r'delete/$',
        SecurePostDelete.as_view(),
        name='blog_securepost_delete'),

    url(r'^(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/$',
        PostDetail.as_view(),
        name='blog_post_detail'),
    url(r'^(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/'
        r'delete/$',
        PostDelete.as_view(),
        name='blog_post_delete'),
     url(r'^(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/'
        r'Secureupdate/$',
        SecurePostUpdate.as_view(),
        name='blog_securepost_update'),
    url(r'^(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/'
        r'(?P<slug>[\w\-]+)/'
        r'update/$',
        PostUpdate.as_view(),
        name='blog_post_update'),
    url(r'^SecureNote/'
        r'(?P<year>\d{4})/$',
        SecurePostArchiveYear.as_view(),
        name='blog_securepost_archive_year'),
url(r'^SecureNote/(?P<year>\d{4})/'
        r'(?P<month>\d{1,2})/$',
        SecurePostArchiveMonth.as_view(),
        name='blog_securepost_archive_month'),
]
