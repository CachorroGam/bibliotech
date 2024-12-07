from django.db import models
from django.contrib.auth.models import User
from PIL import Image
from django.core.validators import MinLengthValidator
from django.utils import timezone



class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    role = models.CharField(
        max_length=50, 
        choices=[
            ('Administrador', 'Administrador'), 
            ('Usuario', 'Usuario'),
            ('Empleado', 'Empleado'),
        ], 
        default='Usuario' 
    )

    avatar = models.ImageField(default='default.jpg', upload_to='profile_images')
    bio = models.TextField()
    numero_membresia = models.BigIntegerField(unique=True, null=True, blank=True)  
    fecha_registro = models.DateTimeField(default=timezone.now)

    ESTADO_MEMBRESIA_CHOICES = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
    ]
    
    estado_membresia = models.CharField(
        max_length=8, 
        choices=ESTADO_MEMBRESIA_CHOICES, 
        default='activo'
    )  
    
    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    
    def __str__(self):
        return self.user.username

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        img = Image.open(self.avatar.path)
        if img.height > 100 or img.width > 100:
            new_img = (100, 100)
            img.thumbnail(new_img)
            img.save(self.avatar.path)



class Libro(models.Model):
    ESTADO_CHOICES = [
        ('disponible', 'Disponible'),
        ('no_disponible', 'No disponible'),
        ('reservado', 'Reservado'),
        ('prestado', 'Prestado'),
    ]
    TITULO_MAX_LENGTH = 200
    AUTOR_MAX_LENGTH = 100
    GENERO_MAX_LENGTH = 50
    ISBN_MAX_LENGTH = 13

    titulo = models.CharField(max_length=TITULO_MAX_LENGTH)
    autor = models.CharField(max_length=AUTOR_MAX_LENGTH)
    genero = models.CharField(max_length=GENERO_MAX_LENGTH)
    fecha_publicacion = models.DateField()
    isbn = models.CharField(max_length=ISBN_MAX_LENGTH, unique=True, blank=True)
    disponible = models.BooleanField(default=True)
    portada = models.ImageField(upload_to='book_covers/', blank=True, null=True)
    descripcion = models.TextField(blank=True, null=True)  
    reservado = models.BooleanField(default=False)
    reservado_por = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    
    
    



    def generate_isbn(self):
        last_isbn = Libro.objects.order_by('-id').first() 
        if last_isbn:
            last_number = int(last_isbn.isbn)
            return str(last_number + 1) 
        return '1000000000000'  

    def save(self, *args, **kwargs):
        if not self.isbn:
            self.isbn = self.generate_isbn()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.titulo



class Prestamo(models.Model):
    libro = models.ForeignKey(Libro, on_delete=models.CASCADE)
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    fecha_prestamo = models.DateField()  # Usamos DateTimeField para la fecha y hora exacta
    fecha_devolucion = models.DateTimeField(null=True, blank=True)
    estado = models.CharField(
        max_length=10, choices=[('prestado', 'Prestado'), ('devuelto', 'Devuelto')], default='prestado'
    )  
    dias_prestamo = models.IntegerField(null=True, blank=True)

    def marcar_devuelto(self):
        self.estado = 'devuelto'
        self.fecha_devolucion = timezone.now()
        self.save()

    def esta_vencido(self):
        if self.estado == 'prestado' and self.fecha_devolucion is None:
            return timezone.now() > self.fecha_prestamo + timezone.timedelta(days=self.dias_prestamo)
        return False

    def __str__(self):
        return f'{self.usuario.username} - {self.libro.titulo}'





class Auditoria(models.Model):
    accion = models.CharField(max_length=255)
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    fecha = models.DateTimeField(auto_now_add=True)
    detalles = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.accion} por {self.usuario.username} en {self.fecha}"





class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    def __str__(self):
        return self.user.username




class Genero(models.Model):
    nombre = models.CharField(max_length=50)

    def __str__(self):
        return self.nombre