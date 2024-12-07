from django.urls import path
from .views import index, profile, RegisterView
from .views import CustomLoginView
from . import views  
from django.conf.urls.static import static
from .views import profile_view, logout_view
urlpatterns = [
    path('', views.index, name='index'), 
    path('register/', RegisterView.as_view(), name='users-register'),
    path('profile/', profile, name='users-profile'),
    path('login/', views.login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    path('dash_admin/', views.dash_admin, name='dash_admin'),
    path('dash_usuario/', views.dash_usuario, name='dash_usuario'),
    path('dash_empleado/', views.dash_empleado, name='dash_empleado'), 
    
]
