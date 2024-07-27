# Full Authentication Tutorial (Login, Register, Logout & Reset Password)

This tutorial will teach you about authentication and registration in django.

## Getting Started

### 1. Setting up a Django Project

- Create and enter the desired directory for project setup.

- Create a virtual environment using pipenv or other means:

    ```shell
    pip install pipenv
    pipenv shell
    ```

- pipenv de-activation and re-activation

- Install Django:

    ```shell
    pip install django
    ```

- Create a Django project called AuthenticationProject:

    ```shell
    django-admin startproject AuthenticationProject
    ```

- Create an app called Core:

    ```shell
    python manage.py startapp Core
    ```

- Open the project in your code editor.

- Create a templates folder and register it in the project's settings.

- Register the app in the project's settings.

- Create URLs for the app and register them in the project's URLs.

- Setup static files in `settings.py`:

    ```python

    import os # at top of file

    STATIC_URL = '/static/'
    STATIC_ROOT = os.path.join(BASE_DIR,  'staticfiles')
    STATICFILES_DIRS = (os.path.join(BASE_DIR, 'static'), )
    ```

### 5. Getting Template Files from GitHub

   - Download the following HTML templates from GitHub:
     - `index.html`
     - `login.html`
     - `register.html`
     - `forgot_password.html`
     - `password_reset_sent.html`
     - `reset_password.html`

### 6. Making required imports

- Head to your views.py file and import the following:

    ```python
    from django.shortcuts import render, redirect
    from django.contrib.auth.models import User
    from django.contrib.auth import authenticate, login, logout
    from django.contrib.auth.decorators import login_required
    from django.contrib import messages
    from django.conf import settings
    from django.core.mail import EmailMessage
    from django.utils import timezone
    from django.urls import reverse
    from .models import *
    ```

### 7. Create a super user

- Create a super user:

```python
python manage.py createsuperuser
```

- login to admin dashboard with credentials:
    `127.0.0.1:8000/admin`

### 8. Creating Home, Register, & Login Views

- Create home view:

    ```python
    def Home(request):
        return render(request, 'index.html')
    ```

- Create two new views for `Register` and `Login`:

    ```python
    def RegisterView(request):
        return render(request, 'register.html')

    def LoginView(request):
        return render(request, 'login.html')
    ```

- Map views to urls:

    ```python
    path('', views.Home, name='home'),
    path('register/', views.RegisterView, name='register'),
    path('login/', views.LoginView, name='login'),
    ```

### 9. Working on Register View

- Change static file links in all files: 

    ```html
    <link rel="stylesheet" href="{% static 'style.css' %}">
    ```

- Head to register.html and give input fields a name attribute & add csrf_token and change the login url:

    ```html
    <form method="POST">

        {% csrf_token %}
      
        <div class="txt_field">
            <input type="text" required name="first_name">
            <span></span>
            <label>First Name</label>
          </div>

          <div class="txt_field">
            <input type="text" required name="last_name">
            <span></span>
            <label>Last Name</label>
          </div>

        <div class="txt_field">
          <input type="text" required name="username">
          <span></span>
          <label>Username</label>
        </div>

        <div class="txt_field">
            <input type="email" required name="email">
            <span></span>
            <label>Email</label>
          </div>

        <div class="txt_field">
          <input type="password" required name="password">
          <span></span>
          <label>Password</label>
        </div>    

        <!-- <div class="pass">Forgot Password?</div> -->
        <input type="submit" value="Register">
        <div class="signup_link">
          Already have an account? <a href="{% url 'login' %}">Login</a>
        </div>
      </form>
    ```

- In `RegisterView` view Check for incoming form submission and grab user data:

    ```python
    if request.method == 'POST:

        # getting user inputs from frontend
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
    ```

- validate the data provided:

    - create flag for error

        ```python
        user_data_has_error = False
        ```
    - validate email and username:

        ```python
        # make sure email and username are not being used

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, 'Username already exists')

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, 'Email already exists')
        ```
    - validate password length:

        ```python
        # make aure password is at least 5 characters long
        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, 'Password must be at least 5 characters')
        ```

- Create a new user if there are no errors and redirect to the login page. Else redirect back to the register page with errors

    ```python
    if not user_data_has_error:
        new_user = User.objects.create_user(
            first_name = first_name,
            last_name = last_name,
            email = email,
            username = username,
            password = password
        )
        messages.success(request, 'Account created. Login now')
        return redirect('login')
    else:
        return redirect('register')
    ```

- Display incoming messages in `register.html`, `login.html`, `forgot_password.html`, and `reset_password.html` files:

    ```html
    {% if messages %}
        {% for message in messages %}
            {% if messages.tags == 'error' %}
                <center><h4 style="color: firebrick;">{{message}}</h4></center>
            {% else %}
                <center><h4 style="color: dodgerblue;">{{message}}</h4></center>
            {% endif %}
        {% endfor %}
    {% endif %}

    <form method="POST">
        ...
    </form>
    ```

- Test code to see if users can now register

### 10. Working on Login View

- Head to login.html and give input fields a name attribute & add csrf_token and change the register url:

    ```html
    <form method="POST">
        {% csrf_token %}

        <div class="txt_field">
          <input type="text" required name="username"> 
          <span></span>
          <label>Username</label>
        </div>

        <div class="txt_field">
          <input type="password" required name="password">
          <span></span>
          <label>Password</label>
        </div>

        <input type="submit" value="Login">
        <div class="signup_link">
          Not a member? <a href="{% url 'register %}">Signup</a>
          <p>Forgot your Password? <a href="#">Reset Password</a></p> 
        </div>
      </form>
    ```

- In `LoginView` view Check for incoming form submission and grab user data:

    ```python
    if request.method == 'POST:

        # getting user inputs from frontend
        username = request.POST.get('username')
        password = request.POST.get('password')
    ```

- Authenticate the user details:

    ```python

    # authenticate credentials
        user = authenticate(request=request, username=username, password=password)
        if user is not None:
            # login user if login credentials are correct
            login(request, user)

            # ewdirect to home page
            return redirect('home')
        else:
            # redirect back to the login page if credentials are wrong
            messages.error(request, 'Invalid username or password')
            return redirect('login')
    ```

- Restrict access to home page to authenticated users:

    ```python
    @login_required # restrict page to authenticated users
    def Home(request):
        return render(request, 'index.html')
    ```

- Set `LOGIN_URL` in `settings.py` file:

    ```python
    # where authenticated user gets redirected to when they try to access a login required view
    LOGIN_URL = 'login'
    ```

- Test if users can login

### 11. Logout View

- Create logout view:

    ```python
    def LogoutView(request):

        logout(request)

        # redirect to login page after logout
        return redirect('login')
    ```

- Map view to url:

    ```python
    path('logout/', views.LogoutView, name='logout')
    ```

- Head to `login.html` file and replace the logout url:

    ```html
    <a href="{% url 'logout' %}">Logout</a>
    ```

### 12. Forgot Password Model & Views

- Create the following views:

    ```python
    def ForgotPassword(request):
        return render(request, 'forgot_password.html')

    def PasswordResetSent(request, reset_id):
        return render(request, 'password_reset_sent.html')

    def ResetPassword(request, reset_id):
        return render(request, 'reset_password.html')
    ```

- Map views to urls:

    ```python
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),
    ```

- Create the following model for the password reset:

    ```python
    from django.db import models
    from django.contrib.auth.models import User
    import uuid

    class PasswordReset(models.Model):
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
        created_when = models.DateTimeField(auto_now_add=True)

        def __str__(self):
            return f"Password reset for {self.user.username} at {self.created_when}"
    ```

- Run:
    ```shell
    python manage.py makemigrations
    python manage.py migrate
    ```

- Register model in admin:

    ```python
    from .models import *

    admin.site.register(PasswordReset)
    ```

### 13. Forgot Password View

- Head to `forgot_password.html` file
- Add a name attribute to input field
- Add csrf_token
- Change url:

    ```html
    <form method="POST">
        {% csrf_token %}
        <div class="txt_field">
          <input type="email" required name="email">
          <span></span>
          <label>Email</label>
        </div>
        
        <input type="submit" value="Reset Password">
        <div class="signup_link">
          Not a member? <a href="{% url 'register %}">Signup</a>
          <p>Remember your Password? <a href="{% url 'login %}">Login</a></p> 
        </div>
    </form>
    ```

- In `ForgotPassword` view Check for incoming form submission to grab user email:

    ```python
    if request.method == 'POST':
        email = request.POST.get('email')
    ```

- Setup email settings so we can send password reset email:

    ```python
    EMAIL_HOST="smtp.gmail.com"
    EMAIL_PORT=465
    EMAIL_USE_SSL=True
    EMAIL_HOST_USER="email@gmail.com"
    EMAIL_HOST_PASSWORD="google app password"
    ```

    For gmail users, create an app password below:

    `https://myaccount.google.com/apppasswords`
    &nbsp;

- Verift if email is valid:

    ```python
    if request.method == 'POST':
        email = request.POST.get('email')

        # verify if email exists
        try:
            user = User.objects.get(email=email)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')
    ```

- Send password reset email if email is valid:

    ```python
    if request.method == 'POST':
        email = request.POST.get('email')

        # verify if email exists
        try:
            user = User.objects.get(email=email)

            # create a new reset id
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            # creat password reset ur;
            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            # email content
            email_body = f'Reset your password using the link below:\n\n\n{password_reset_url}',

            email_message = EmailMessage(
                'Reset your password', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent')

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')
    ```

### 14. Password Reset Sent View:

- Get reset_id and make sure that it is valid:

    ```python
    def PasswordResetSent(request, reset_id):

        if PasswordReset.objects.filter(reset_id=reset_id).exists():
            return render(request, 'password_reset_sent.html')
        else:
            # redirect to forgot password page if code does not exist
            messages.error(request, 'Invalid reset id')
            return redirect('forgot-password')
    ```    

### 15. Password Reset View

- Head to the `reset_password.html` file and make sure that you add the name attributes and csrf_token:

    ```html
    <form method="POST">
        
        {% csrf_token %}

        <div class="txt_field">
          <input type="password" required name="password">
          <span></span>
          <label>Password</label>
        </div>    

        <div class="txt_field">
            <input type="password" required name="confirm_password">
            <span></span>
            <label>Confirm Password</label>
        </div>    

        <input type="submit" value="Register">
        <div class="signup_link">
          Remember your password? <a href="{% url 'login' %}">Login</a>
        </div>
      </form>
    ```

- Get reset_id and make sure that it is valid:

    ```python
    def ResetPassword(request, reset_id):

        try:
            reset_id = PasswordReset.objects.get(reset_id=reset_id)
        
        except PasswordReset.DoesNotExist:
            
            # redirect to forgot password page if code does not exist
            messages.error(request, 'Invalid reset id')
            return redirect('forgot-password')

        return render(request, 'reset_password.html')
    ```    

- Get passwords from form submit:

    ```python
    if request.method == 'POST':

        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
    ```

- Verify passwords and reset link:

    ```python
    if request.method == 'POST':

        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        passwords_have_error = False

        if password != confirm_password:
            passwords_have_error = True
            messages.error(request, 'Passwords do not match')

        if len(password) < 5:
            passwords_have_error = True
            messages.error(request, 'Password must be at least 5 characters long')

        # check to make sure link has not expired
        expiration_time = reset_id.created_when + timezone.timedelta(minutes=10)

        if timezone.now() > expiration_time:
            passwords_have_error = True
            messages.error(request, 'Reset link has expired')
    ```

- Reset password:

    ```python
    if request.method == 'POST':

        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        passwords_have_error = False

        if password != confirm_password:
            passwords_have_error = True
            messages.error(request, 'Passwords do not match')

        if len(password) < 5:
            passwords_have_error = True
            messages.error(request, 'Password must be at least 5 characters long')

        expiration_time = reset_id.created_when + timezone.timedelta(minutes=10)

        if timezone.now() > expiration_time:

            # delete reset id if expired
            reset_id.delete()

            passwords_have_error = True
            messages.error(request, 'Reset link has expired')
        
        # reset password
        if not passwords_have_error:
            user = reset_id.user
            user.set_password(password)
            user.save()
            
            # delete reset id after use
            reset_id.delete()

            # redirect to login
            messages.success(request, 'Password reset. Proceed to login')
            return redirect('login')

        else:
            # redirect back to password reset page and display errors
            return redirect('reset-password', reset_id=reset_id)
    ```


### 16. Test The Code

### 17. Prevent authenticated users from visiting auth pages