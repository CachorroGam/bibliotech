from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.forms import AuthenticationForm
from .models import Profile
from .models import Libro
from .models import Prestamo, Libro
from users.models import Prestamo


class RegisterForm(UserCreationForm):
    # fields we want to include and customize in our form
    first_name = forms.CharField(max_length=100,
                                 required=True,
                                 widget=forms.TextInput(attrs={'placeholder': 'First Name',
                                                               'class': 'form-control',
                                                               }))
    last_name = forms.CharField(max_length=100,
                                required=True,
                                widget=forms.TextInput(attrs={'placeholder': 'Last Name',
                                                              'class': 'form-control',
                                                              }))
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={'placeholder': 'Username',
                                                             'class': 'form-control',
                                                             }))
    email = forms.EmailField(required=True,
                             widget=forms.TextInput(attrs={'placeholder': 'Email',
                                                           'class': 'form-control',
                                                           }))
    password1 = forms.CharField(max_length=50,
                                required=True,
                                widget=forms.PasswordInput(attrs={'placeholder': 'Password',
                                                                  'class': 'form-control',
                                                                  'data-toggle': 'password',
                                                                  'id': 'password',
                                                                  }))
    password2 = forms.CharField(max_length=50,
                                required=True,
                                widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password',
                                                                  'class': 'form-control',
                                                                  'data-toggle': 'password',
                                                                  'id': 'password',
                                                                  }))

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={'placeholder': 'Username',
                                                             'class': 'form-control',
                                                             }))
    password = forms.CharField(max_length=50,
                               required=True,
                               widget=forms.PasswordInput(attrs={'placeholder': 'Password',
                                                                 'class': 'form-control',
                                                                 'data-toggle': 'password',
                                                                 'id': 'password',
                                                                 'name': 'password',
                                                                 }))
    remember_me = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ['username', 'password', 'remember_me']


class UpdateUserForm(forms.ModelForm):
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=True,
                             widget=forms.TextInput(attrs={'class': 'form-control'}))

    class Meta:
        model = User
        fields = ['username', 'email']


class UpdateProfileForm(forms.ModelForm):
    avatar = forms.ImageField(widget=forms.FileInput(attrs={'class': 'form-control-file'}))
    bio = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}))

    class Meta:
        model = Profile
        fields = ['avatar', 'bio']





class LoginForm(AuthenticationForm):
    remember_me = forms.BooleanField(required=False, initial=False)




class LibroForm(forms.ModelForm):
    class Meta:
        model = Libro
        fields = ['titulo', 'autor', 'genero', 'fecha_publicacion', 'isbn', 'disponible', 'portada', 'descripcion']
        widgets = {
            'fecha_publicacion': forms.DateInput(attrs={'type': 'date'}),
        }





class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']





class ContactForm(forms.Form):
    nombre = forms.CharField(max_length=100)
    email = forms.EmailField()
    asunto = forms.CharField(max_length=100)
    mensaje = forms.CharField(widget=forms.Textarea)





class PrestamoForm(forms.ModelForm):
    class Meta:
        model = Prestamo
        fields = ['usuario', 'libro', 'fecha_devolucion', 'estado', 'dias_prestamo']
        
    libro = forms.ModelChoiceField(queryset=Libro.objects.all(), empty_label="Selecciona un libro")




class EditarPrestamoForm(forms.ModelForm):
    class Meta:
        model = Prestamo
        fields = ['libro', 'usuario', 'fecha_devolucion', 'estado', 'dias_prestamo', 'fecha_prestamo']  # Campos editables
        widgets = {
            'dias_prestamo': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
            'estado': forms.Select(attrs={'class': 'form-control'}),
        }

        fecha_prestamo = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
        )

        def clean(self):
            cleaned_data = super().clean()
            fecha_prestamo = cleaned_data.get('fecha_prestamo')
            fecha_devolucion = cleaned_data.get('fecha_devolucion')

            if fecha_prestamo and fecha_devolucion:
                dias_prestamo = (fecha_devolucion - fecha_prestamo).days
                cleaned_data['dias_prestamo'] = dias_prestamo
            
            return cleaned_data
    
