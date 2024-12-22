from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.cache import cache_control
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import re


# Create your views here.


@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def index(request):
    return render(request, 'index.html')


@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def signup(request):
    if request.user.is_authenticated:
        return redirect('welcome')
    
    if request.method == "POST":
    
        fullname = request.POST.get('fullname')  # Get 'fullname' from the form
        username = request.POST.get('username')  # Get 'username' from the form
        email = request.POST.get('email')        # Get 'email' from the form
        password = request.POST.get('password')  # Get 'password' from the form
        confirm_password = request.POST.get('confirm_password')
        
        #validation
        
        if not re.match(r"^[A-Za-z]+(?: [A-Za-z]+)*$", fullname):
            messages.error(request, 'Invalid first name, please enter a valid input.')
            return redirect('signup')

        if not re.match(r"^[A-Za-z]+(?: [A-Za-z]+)*$", username):
            messages.error(request, 'Invalid username, please enter a valid input.')
            return redirect('signup')

        if not re.match(r"^[A-Za-z\._\-0-9]+@[A-Za-z]+\.[a-z]{2,4}$", email):
            messages.error(request, 'Invalid email, please enter a valid emali.')
            return redirect('signup')
        
        if password != confirm_password:
            messages.error(request, 'Password not match, please retry.')
            return redirect('signup')
        
        if len(password) < 8 or password.isspace():
            messages.error(request, 'Password must be at least 8 characters and cannot contain only spaces.')
            return redirect('signup')

        # Create a new user
        User.objects.create_user(first_name=fullname, username=username, email=email, password=password)

        # Redirect to login page
        messages.success(request,'Registration sucessfull.')
        return redirect('loginn')

    return render(request, 'signup.html')


@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def loginn(request):
    if request.user.is_authenticated:
        return redirect('welcome')
    
    if request.method=='POST':
        username=request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            messages.error(request, 'Username or password not entered.')
            return redirect('loginn')
        
        user=authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('welcome')
        
        else:
            messages.error(request,'Invalid username or password.')
            return redirect('loginn')
            
    return render(request, 'login.html')


@login_required(login_url='loginn')
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def welcome(request):
    return render(request,'welcome.html')

def contact(request):
    return render(request,'contact.html')


@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def logout_view(request):
    logout(request)
    return redirect('loginn')  # Redirect to login page after logout
