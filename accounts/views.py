from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required


def signup(request):
    """
    Handles user signup requests.

    Validates user input, creates a new user account, and redirects to the login page.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password")
        password2 = request.POST.get("confirm_password")

        if not username or not email or not password1 or not password2:
            messages.error(request, "Please fill in all required fields.")
            return render(request, "signup.html")
        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, "signup.html")
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, "signup.html")

        user = User.objects.create_user(username, email, password1)
        user.save()
        messages.success(request, "Account created successfully!")
        return redirect("accounts:signin")
    else:
        return render(request, "signup.html")


def signin(request):
    """
    Handles user login requests.

    Authenticates the user, logs them in, and redirects to the dashboard.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {username}!")
            return redirect("core:dashboard")
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("accounts:signin")
    else:
        return render(request, "signin.html")


@login_required
def signout(request):
    """
    Handles user logout requests.

    Logs out the user and redirects to the login page.
    """
    auth.logout(request)
    messages.info(request, "You have logged out from SIEM.")
    return redirect("accounts:signin")
