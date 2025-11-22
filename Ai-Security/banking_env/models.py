from django.db import models


from django.db import models
from django.contrib.auth.models import User

class BankAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=20, unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
    ]
    
    from_account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='sent_transactions')
    to_account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='received_transactions', null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    description = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
class VulnerableUser(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)  # Mot de passe en texte clair
    email = models.EmailField(blank=True)
    
    def __str__(self):
        return self.username