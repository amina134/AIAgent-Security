import os
import sys
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from banking_env.models import BankAccount, UserProfile, VulnerableUser

class Command(BaseCommand):
    help = "Create test users and their bank accounts for vulnerability testing"
    
    def handle(self, *args, **options):
        # Create regular Django users
        test_users = [
            {'username': 'ranim', 'password': 'password123', 'balance': 5000},
            {'username': 'ghada', 'password': 'password123', 'balance': 3000},
            {'username': 'amina', 'password': 'password123', 'balance': 1000},
        ]
        
        for user_data in test_users:
            user, created = User.objects.get_or_create(username=user_data['username'])
            if created:
                user.set_password(user_data['password'])  # FIXED: Use set_password()
                user.save()
                
                # Create bank account 
                account = BankAccount.objects.create(
                    user=user,
                    account_number=f"ACC{user.id:06d}",
                    balance=user_data['balance']
                )
                
                # Create user profile 
                UserProfile.objects.create(user=user)
                self.stdout.write(self.style.SUCCESS(f'Created user {user.username} with account {account.account_number}'))
        
        # Create VulnerableUsers with PLAIN TEXT passwords for SQL injection
        vulnerable_users = [
            {'username': 'vranim', 'password': 'password123'},
            {'username': 'vghada', 'password': 'password123'},
            {'username': 'vamina', 'password': 'password123'},
        ]
        
        for user_data in vulnerable_users:
            user, created = VulnerableUser.objects.get_or_create(
                username=user_data['username'],
                defaults={'password': user_data['password'], 'email': ''}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created VULNERABLE user {user.username} with password: {user.password}'))