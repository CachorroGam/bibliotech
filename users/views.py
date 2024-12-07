from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.views import View
from django.contrib.auth.models import Group
from django.shortcuts import redirect, render
from .models import Profile
from django.db.models import Max
from .forms import RegisterForm, LoginForm, UpdateUserForm, UpdateProfileForm
from django.db.models import Count
from .models import Prestamo, Libro
from .models import UserProfile
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from .models import Libro
from django.shortcuts import render, get_object_or_404
from .forms import LibroForm
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.models import User, Group
from .forms import UserForm  
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import Libro, Prestamo
from django.utils import timezone
from users.models import Prestamo
from .forms import EditarPrestamoForm
from datetime import datetime
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import logout
from django.utils.decorators import decorator_from_middleware
from django.middleware.cache import CacheMiddleware


admin_group, created = Group.objects.get_or_create(name='Administrador')
empleado_group, created = Group.objects.get_or_create(name='Empleado')  
usuario_group, created = Group.objects.get_or_create(name='Usuario')


def index(request):
    libros = Libro.objects.all() 
    return render(request, 'users/index.html', {'libros': libros})




class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'users/register.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(to='/')
        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)

        if form.is_valid():
            user = form.save()

            user_group = Group.objects.get(name='Usuario')
            user.groups.add(user_group)

            last_membership = Profile.objects.aggregate(Max('numero_membresia'))['numero_membresia__max']
            if last_membership is None:
                numero_membresia = 100000 
            else:
                numero_membresia = last_membership + 1 

            print(f'Último número de membresía: {last_membership}, Nuevo número de membresía: {numero_membresia}')

            profile, created = Profile.objects.get_or_create(
                user=user,
                defaults={'numero_membresia': numero_membresia, 'role': 'Usuario', 'avatar': 'default.jpg', 'bio': ''}
            )

            if not created and profile.numero_membresia is None:
                profile.numero_membresia = numero_membresia
                profile.save()

            if created:
                messages.success(request, f'Cuenta creada para {user.username} con el número de membresía {numero_membresia}')
            else:
                messages.info(request, f'Ya existe un perfil para {user.username}. Número de membresía: {profile.numero_membresia}')

            return redirect(to='login')

        return render(request, self.template_name, {'form': form})



class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            self.request.session.set_expiry(0)
            self.request.session.modified = True

        user = self.request.user

        if user.groups.filter(name='Administradores').exists():
            messages.success(self.request, '¡Bienvenido Administrador!')
            return redirect('users/dash_admin') 

        elif user.groups.filter(name='Empleados').exists():
            messages.success(self.request, '¡Bienvenido Empleado!')
            return redirect('users/dash_empleado') 

        elif user.groups.filter(name='Lectores').exists():
            messages.success(self.request, '¡Bienvenido Lector!')
            return redirect('users/dash_lector') 

        messages.success(self.request, '¡Bienvenido a la plataforma!')
        return super().form_valid(form)


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')


class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('users-home')


@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})



def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            if user.groups.filter(name='Administrador').exists():
                return redirect('dash_admin')
            elif user.groups.filter(name='Empleado').exists(): 
                return redirect('dash_empleado')
            elif user.groups.filter(name='Usuario').exists():
                return redirect('dash_usuario')
            else:
                return render(request, 'sin_permiso.html', {'mensaje': 'No tiene rol asignado'})
    else:
        form = AuthenticationForm()
    return render(request, 'users/login.html', {'form': form})



@login_required
def profile_view(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    response = render(request, 'users/profile.html', {'user_profile': user_profile})
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response






def logout_view(request):
    logout(request) 
    return redirect('login')  





def no_cache(view_func):
    def _wrapped_view_func(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        return response
    return _wrapped_view_func




def dash_admin(request):
    total_libros = Libro.objects.count()
    libros_disponibles = Libro.objects.filter(disponible=True).count()
    total_prestamos = Prestamo.objects.count()
    prestamos_activos = Prestamo.objects.filter(estado='prestado').count()

    libros_mas_prestados = Prestamo.objects.values('libro__titulo') \
        .annotate(total=Count('libro')) \
        .order_by('-total')[:5]

    context = {
        'total_libros': total_libros,
        'libros_disponibles': libros_disponibles,
        'total_prestamos': total_prestamos,
        'prestamos_activos': prestamos_activos,
        'libros_mas_prestados': libros_mas_prestados
    }

    return render(request, 'users/dash_admin.html', context)






def dash_empleado(request):
    total_libros = Libro.objects.count()
    libros_disponibles = Libro.objects.filter(disponible=True).count()
    total_prestamos = Prestamo.objects.count()
    prestamos_activos = Prestamo.objects.filter(estado='prestado').count()

    libros_mas_prestados = Prestamo.objects.values('libro__titulo') \
        .annotate(total=Count('libro')) \
        .order_by('-total')[:5]

    context = {
        'total_libros': total_libros,
        'libros_disponibles': libros_disponibles,
        'total_prestamos': total_prestamos,
        'prestamos_activos': prestamos_activos,
        'libros_mas_prestados': libros_mas_prestados
    }

    return render(request, 'users/dash_empleado.html', context)




def dash_usuario(request):
    libros = Libro.objects.all() 
    return render(request, 'users/dash_usuario.html', {'libros': libros})

