from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string

def send_verification_email(user_email):
    send_mail(
        subject=("Welcome to your {} Account!").format("ice-cream"),
        message="verify your account",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False      
    )

def send_password_reset_email(user, reset_url):
    send_mail(
        subject='Password Reset Request',
        message=f'Click the link to reset your password: {reset_url}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user],
        fail_silently=False   
        )