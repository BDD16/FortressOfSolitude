"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2021
Proof of Concept code, No liabilities or warranties expressed or implied.
"""


from _FortressOfSolitude.NeutrinoKey.decorators import custom_login_required
from _FortressOfSolitude.core.utils import UpdateView
from _FortressOfSolitude.organizer.models import (ImageFile, MusicFile, MiscFile, Gor_El)
from _FortressOfSolitude.superhero.decorators import require_authenticated_permission
from django.contrib.auth import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import permission_required
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import (get_object_or_404, redirect, render)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import (FormView, ListView, View)
from django.views.generic.detail import SingleObjectMixin

from .forms import TagForm, TaskingForm, UploadFileForm
from .models import Tag, Tasking
from .utils import CreateView


#experimental feature for progress bar
# Create your views here.
def homepage(request):
    return render(request, 'organizer/tag_list.html', {'tag_list': Tag.objects.all()})

def tag_detail(request, slug):
    tag = get_object_or_404(Tag, slug__iexact=slug)
    return render(request, 'organizer/tag_detail.html', {'tag': tag})

def tasking_detail(request, slug):
    tasking = get_object_or_404(Tasking, slug__iexact=slug)
    return render(request, 'organizer/tasking_detail.html', {'tasking': tasking})


def tag_list(request):
    return render(request, 'organizer/tag_list.html', {'tag_list': Tag.objects.all()})

def download_list(request):
    return render(request, 'organizer/download.html', {'download_list': ImageFile.objects.all()})

#def download_file(request, file):
#    plain = handle_downloaded_file(file, request)
#    if plain != None:
#        response = HttpResponse(plain, content_type="application/vnd." + str(request).[-3:] )
#        response['Content-Disposition'] = 'inline; filename=' + str(f)
#        return response
#    else:
#        raise Http404
#    return handle_downloaded_file(file, request)

class DownloadView(View):
    mimetype = None
    extension = None
    filename = None
    use_xsendfile = True

    def get_filename(self):
        return self.filename

    def get_extension(self):
        return self.extension

    def get_mimetype(self):
        return self.mimetype

    def get_location(self):
        pass

    def get_contents(self):
        pass

    def get(self, request, *args, **kwargs):
        response = HttpResponse(content_type=self.get_mimetype())
        print('yolo')
        response['Content-Disposition'] = 'filename=' + self.get_filename()

        if self.use_xsendfile is True:
            response['X-Sendfile'] = self.get_location()

        else:
            print("made it here! on Gor_El decryption")
            unwrapThis = self.get_contents()
            if not isinstance(unwrapThis, ImageFile):
                unwrapThis = ImageFile(unwrapThis)
            response.write(handle_downloaded_file(unwrapThis, request))

        return response


class DownloadTheGoodsView(SingleObjectMixin, DownloadView):
    model = ImageFile

    use_xsendfile = False
    mimetype = 'application/png'

    def get_contents(self):
        return self.get_object()

    def get_filename(self):
        return str(self.get_object().image_file).split('.')[0]

class TagList(ListView):
    model = Tag
    template_name = 'organizer/tag_list.html'

    @method_decorator(login_required)
    #@method_decorator(permission_required('organizer.view_tag', raise_exception=True))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

def redirect_root(request):
    url_path = reverse('blog_post_list')
    return HttpResponseRedirect(url_path)

def tag_create(request):
    if request.method == 'POST':
        form = TagForm(request.POST)
        if form.is_valid():
            new_tag = form.save()
            return redirect(new_tag)
        else:
            return render(request, 'organizer/tag_form.html', {'form': form})
    else:
        form = TagForm()
    return render(request, 'organizer/tag_form.html', {'form': form})

def tasking_create(request):
    if request.method == 'POST':
        form = TaskingForm(request.POST)
        print("before forms.isvalid()")
        print(form)
        print("\n\n")
        if form.is_valid():
            print(form)
            new_tasking = form.save()
            return redirect(new_tasking)
        else:
            return render(request, 'organizer/tasking_form.html', {'form':form})
    else:
        form = TaskingForm()
    return render(request, 'organizer/tasking_form.html', {'form': form})

def in_contrib_group(user):
    if user.groups.filter(name='contributors').exists():
        return True
    else:
        raise PermissionDenied

class DownloadImageList(ListView):
    model = ImageFile
    template_name = 'organizer/imagefile_list.html'
    #success_url = reverse_lazy('organizer_upload_success')

    #@method_decorator(permission_required('organizer.download_file', login_url='/login/', raise_exception=True))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)



@require_authenticated_permission('organizer.view_tasking')
class TaskingList(ListView):
    model = Tasking
    template_name = 'organizer/tasking_list.html'

    @method_decorator(permission_required('organizer.view_tasking',login_url='/login/', raise_exception=True))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@require_authenticated_permission('organizer.add_tag')
class TagCreate(CreateView):
    form_class = TagForm
    model = Tag
    template_name = 'organizer/tag_form.html'

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@require_authenticated_permission('organizer.add_tasking')
class TaskingCreate(CreateView):
    form_class = TaskingForm
    model = Tasking
    template_name = 'organizer/tasking_form.html'

    #@method_decorator(login_required)
    @method_decorator(permission_required('organizer.view_tasking',login_url='/login/', raise_exception=True))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@require_authenticated_permission('organizer.update_tasking')
class TaskingUpdate(UpdateView):
    form_class = TaskingForm
    model = Tasking

@require_authenticated_permission('organizer.update_tag')
class TagUpdate( UpdateView):
    form_class = TagForm
    model = Tag
    template_name_suffix = '_form_update'

    @method_decorator(login_required)
    @method_decorator(permission_required('organizer.add_tag', raise_exception=True))
    @method_decorator(custom_login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

class SuccessView(View):
    template_name = 'organizer/uploadsuccess.html'
    def dispatch(self, request, *args, **kwargs):
        return render(request, 'organizer/uploadsuccess.html')
#'''
#class DownloadView(FormView):
#    form_class = DownloadFileForm
#    success_url = reverse)_lazy('organizer_download_success')

#    def post(self, request, *args, **kwargs):
#        self.object = None
#        form = self.form_class(request)

#'''



class UploadFile(FormView): #CreateView
    form_class = UploadFileForm
    template_name = 'organizer/upload.html'
    success_url = reverse_lazy('organizer_upload_success')

    def post(self, request, *args, **kwargs):
        self.object = None
        form = self.form_class(request)
        file = request.FILES.getlist('file_field')
        filez = request.FILES.getlist('file_field')
        total_work = len(filez)
        i = 0
        if form.is_valid:
            for f in filez:

                ####generate AES-KEY pwd protect with password
                ####TODO: Encrypt
                print(str(f))
                #task_status(i, total_work)
                if str(f).lower().endswith(('.png','.jpg','.jpeg','.tiff')):
                    print("storing file: " + str(f))
                    enc = handle_image_uploaded_file(ImageFile(f), request) #create temporary file
                    #Just a test here to see if we can decrypt everything using print statements:
                    print(dir(enc))
                    #handle_downloaded_file(enc, request, i, total_work)
                elif str(f).lower().endswith(('.mp3', '.flac', '.aac', '.m4p')):
                    print("storing file: " + str(f))
                    enc = handle_music_uploaded_file(MusicFile(f), request) #create temporary file
                    #make sure we can decrypt in this case
                    enc = handle_downloaded_file(enc, request) #Take out before final production
                    #View output form to make sure that everythign was outputted correctly i.e. no encryption or decryption error
                else:
                    print("storing file: " + str(f))
                    enc = handle_misc_uploaded_file(MiscFile(f), request)
                    #make sure we can decrypt in this case
                    enc = handle_downlaoded_file(enc, request)#Take out before final production
                    #View output form to make sure that everything was outputted correctly i.e. no encryption or decryption error

                i += 1
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

def handle_misc_uploaded_file(f, request):
    if (request.user != None):
        encryptedObj = MiscFile.objects._encrypt_data(str(request.user.password), image_file=f, request=request)


        return encryptedObj

def handle_music_uploaded_file(f, request):
    if(request.user != None):
        encryptedObj = MusicFile.objects._encrypt_data(str(request.user.password), image_file=f, request=request)

        return encryptedObj

def handle_image_uploaded_file(f, request):
    if(request.user != None):
        encryptedObj = ImageFile.objects._encrypt_data(str(request.user.password), image_file=f, request=request)

        return encryptedObj


#LEGACY FUNCTION USED FOR DEVELOPMENT AND HISTORICAL PURPOSES. DEPRECATED 3/06/2020

def handle_uploaded_file(f, request):
    #Right now it is unencrypted. adjust to add in encryption
    print(request.user.password)
    print(dir(request.user.password))


    if(request.user != None):
        #encrypt temporary file

        #Fetch KEK,

        #Generate SALT

        #Store Salt

        #Derive DEK

        #All of the above steps are handled in the below function!!! woohoo!

        #Encrypt and do all the above steps in one function!
        encryptedObj = ImageFile.objects._encrypt_data(str(request.user.password), image_file=f, request=request)

        return encryptedObj
    # with open(f., 'wb+') as destination:
    #    for chunk in f.chunks():
    #        destination.write(chunk)

#@task
def handle_downloaded_file(f, request, i=0, total_work=100):
    if request.user != None:
        AskMeAQuestionAndIShallAnswer = Gor_El()

        # current_task.update_state(state='PROGRESS',
        #                          meta={'current': i, 'total': total_work})
        print(str(request.user.password))
        ans = AskMeAQuestionAndIShallAnswer._decrypt_data(str(request.user.password), request=request, image_file=f)

        print("This is the answer to the question you asked: ")
        print(ans)
        return ans
#'''
#def task_status(request, task_id):
#    result = AsyncResult(task_id)

#    response_data = {
#        'state' : result.state,
#        'details' : result.info,
#        }
#    return HttpResponse(json.dumps(response_data), content_type='application/json')
#'''
