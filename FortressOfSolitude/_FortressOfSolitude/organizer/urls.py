"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""


from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static
from django.contrib.auth.decorators import login_required

from .views import tag_detail, tasking_detail, TagCreate, TaskingCreate, UploadFile, TaskingList, TagList, \
    TaskingUpdate, SuccessView, DownloadImageList, DownloadTheGoodsView  # , task_status

urlpatterns = [
    url(r'^$',
        login_required(TagList.as_view()),
        name='organizer_tag_list'),
    url(r'^tag/create/$',
        login_required(TagCreate.as_view()),
        name='organizer_tag_create'),
    url(r'^tasking/create/$',
        login_required(TaskingCreate.as_view()),
        name='organizer_tasking_create'),
    url(r'^tag/(?P<slug>[\w\-]+)/$',
        tag_detail,
        name='organizer_tag_detail'),
    url(r'^tasking/(?P<slug>[\w\-]+)/$',
        tasking_detail,
        name='organizer_tasking_detail'),
    url(r'^create/$',
        login_required(TagCreate.as_view()),
        name='organizer_tag_create'),
    url(r'^upload/create/$',
        login_required(UploadFile.as_view()),
        name='organizer_upload_create'),
    url(r'^upload/create/uploadsuccess/$',
        login_required(SuccessView.as_view()),
        name='organizer_upload_success'),
    url(r'^tasking/$',
        login_required(TaskingList.as_view()),
        name='organizer_tasking_list'),
    url(r'^(?P<slug>[\w\-]+)/update/$',
        login_required(TaskingUpdate.as_view()),
        name='organizer_tasking_update'),
    url(r'^download/$',
      login_required(DownloadImageList.as_view()),
      name='organizer_download_pull'),
    url('^download/media/photos/(?P<pk>\d+)$',
        login_required(DownloadTheGoodsView.as_view()),
        {'document_root': settings.MEDIA_ROOT}),
      #re_path(r'^download/(?P<path>.*)$', serve, { 'document_root': settings.STATIC_ROOT}),
    #url(r'^(?P<task_id>[\w-]+)/$', task_status, name='task_status')
    ] + static('/media/', document_root=settings.MEDIA_ROOT)
