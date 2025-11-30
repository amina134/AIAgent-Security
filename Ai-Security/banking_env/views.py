from django.http import HttpResponse, JsonResponse
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from .models import BankAccount, Transaction, UserProfile, VulnerableUser
import sqlite3
import time
import os
import json


# -----------------------------
# Home
# -----------------------------
def home(request):
    return render(request, "banking_env/home.html")


# -----------------------------
# Vulnerability 1: SQL Injection (VulnerableUser table)
# -----------------------------
def vulnerable_sql_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        # ❗ VULNERABLE SQL QUERY
        query = f"SELECT id, username, password FROM banking_env_vulnerableuser WHERE username='{username}' AND password='{password}'"
        print("EXECUTED:", query)

        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            return HttpResponse(f'''
                <h2>✅ SQL Injection Successful!</h2>
                <p>Welcome <strong>{user_data[1]}</strong>!</p>
                <p>Password in DB: <code>{user_data[2]}</code></p>
                <p><em>SQL Injection vulnerability exploited</em></p>
                <p><a href="/vulnerable-login">Try again</a> | <a href="/">Home</a></p>
            ''')
        else:
            return HttpResponse('''
                <h2>❌ Login Failed</h2>
                <p>No user found. Try SQL injection payloads.</p>
                <p><a href="/vulnerable-login">Try again</a></p>
            ''')

    return HttpResponse('''
        <h2>🔐 SQL Injection Test</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br><br>
            Password: <input type="password" name="password"><br><br>
            <button type="submit">Login</button>
        </form>
    ''')


# -----------------------------
# Regular Login (safe)
# -----------------------------
def regular_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            return HttpResponse("Invalid credentials")

    return render(request, 'banking_env/login.html')


# -----------------------------
# Vulnerability 2: Reflected XSS
# -----------------------------
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect("/login")

    search = request.GET.get("search", "")

    return render(request, "banking_env/dashboard.html", {"search": search})


# -----------------------------
# Vulnerability 3: CSRF
# -----------------------------

def transfer_money(request):
    if not request.user.is_authenticated:
        return redirect("/regular-login")

    # ❗❗ VULNERABLE GET-BASED TRANSFER
    if request.method == "GET" and "to_account" in request.GET:
        to_account = request.GET.get("to_account")
        amount = request.GET.get("amount")
        return _process_transfer(request, to_account, amount, source="GET (VULNERABLE)")

    # ✔ SAFE USER TRANSFER USING POST
    if request.method == "POST":
        to_account = request.POST.get("to_account")
        amount = request.POST.get("amount")
        return _process_transfer(request, to_account, amount, source="POST (SAFE USER)")

    # SHOW FORM using separate HTML
    return render(request, "banking_env/transfer.html")


def _process_transfer(request, to_account, amount, source):
    try:
        from_account = BankAccount.objects.get(user=request.user)
        to_account_obj = BankAccount.objects.get(account_number=to_account)

        from decimal import Decimal
        amount_dec = Decimal(amount)

        if from_account.balance >= amount_dec:
            from_account.balance -= amount_dec
            to_account_obj.balance += amount_dec
            from_account.save()
            to_account_obj.save()

            Transaction.objects.create(
                from_account=from_account,
                to_account=to_account_obj,
                amount=amount_dec,
                transaction_type="TRANSFER",
                description=f"Transfer ({source})"
            )
            return HttpResponse(f"<h3>Transfer Successful ({source})</h3>")

        return HttpResponse("Insufficient funds")

    except Exception as e:
        return HttpResponse(f"Error: {e}")


# -----------------------------
# Vulnerability 4: IDOR
# -----------------------------
def account_info(request):
    if not request.user.is_authenticated:
        return redirect("/regular-login")

    acc_id = request.GET.get("account_id")
    account = None  # initialize to avoid UnboundLocalError

    if acc_id:
        try:
            account = BankAccount.objects.get(id=acc_id)
            return render(request, "banking_env/account_info.html", {
                "account": account
            })
        except BankAccount.DoesNotExist:
            return HttpResponse("Account not found")

    # Show your own account
    my_account = BankAccount.objects.get(user=request.user)
    return render(request, "banking_env/account.html", {
        "my_account": my_account,

    })

    

# -----------------------------
# Logout
# -----------------------------
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('/')
