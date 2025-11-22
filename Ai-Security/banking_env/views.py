from django.http import HttpResponse, JsonResponse
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from .models import BankAccount, Transaction, UserProfile, VulnerableUser
import sqlite3
import time
import requests
import os
import json

def home(request):
    return render(request, "banking_env/home.html")

# -----------------------------
# Working SQL Injection with VulnerableUser table
# -----------------------------
def vulnerable_sql_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        # VULNERABLE: Query the VulnerableUser table with plain text passwords
        query = f"SELECT id, username, password FROM banking_env_vulnerableuser WHERE username='{username}' AND password='{password}'"
        print("EXECUTED:", query)

        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            # For demo - just show success message
            return HttpResponse(f'''
            <h2>✅ SQL Injection Successful!</h2>
            <p>Welcome <strong>{user_data[1]}</strong>!</p>
            <p>Password in database: <code>{user_data[2]}</code></p>
            <p><em>SQL Injection vulnerability successfully exploited</em></p>
            <p><a href="/vulnerable-login">← Try another payload</a> | <a href="/">Home</a></p>
            ''')
        else:
            return HttpResponse(f'''
            <h2>❌ Login Failed</h2>
            <p>No user found. Try SQL injection payloads below.</p>
            <p><a href="/vulnerable-login">← Try again</a></p>
            ''')

    return HttpResponse('''
    <h2>🔐 SQL Injection Test (Vulnerable Users)</h2>
    <form method="POST">
        Username: <input type="text" name="username" required style="width: 300px; padding: 8px;"><br><br>
        Password: <input type="password" name="password" style="width: 300px; padding: 8px;"><br><br>
        <button type="submit" style="padding: 10px 20px;">Login</button>
    </form>
    
    <div style="margin-top: 30px; background: #f5f5f5; padding: 20px; border-radius: 5px;">
        <h3>🧪 Test Payloads:</h3>
        
        <div style="background: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 5px;">
            <strong>SQL Injection Bypass:</strong><br>
            Username: <code>' OR '1'='1' -- </code><br>
            Password: <em>(leave empty)</em>
        </div>
        
        <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px;">
            <strong>Normal Login:</strong><br>
            Username: <code>vranim</code><br>
            Password: <code>password123</code>
        </div>
        
        <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px;">
            <strong>Other Users:</strong><br>
            Username: <code>vghada</code> or <code>vamina</code><br>
            Password: <code>password123</code>
        </div>
    </div>
    
    <p><a href="/">← Back to Home</a></p>
    ''')

# -----------------------------
# Regular Django Login (for other vulnerabilities)
# -----------------------------
def regular_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('/dashboard')
        else:
            return HttpResponse("Invalid credentials - use: ranim/password123, ghada/password123, amina/password123")

    return render(request, 'banking_env/login.html')

# -----------------------------
# Vulnerability 2: Reflected XSS
# -----------------------------
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect("/regular-login")

    search = request.GET.get("search", "")
    # REFLECTED XSS: unsanitized echo of the query parameter
    return HttpResponse(f'''
    <h2>Banking Dashboard</h2>
    <p>Welcome, {request.user.username}!</p>
    <p><a href="/logout" style="color: red;">🚪 Logout</a></p>

    <form>
        <input type="text" name="search" value="{search}" placeholder="Search transactions">
        <button type="submit">Search</button>
    </form>

    <p>Search results for: {search}</p>

    <div>
        <h3>Quick Actions:</h3>
        <a href="/transfer">💸 Transfer Money</a> |
        <a href="/account">👤 View Account</a> |
        <a href="/">🏠 Home</a>
    </div>
    
    <div style="margin-top: 30px; background: #fff3cd; padding: 15px;">
        <h3>XSS Test:</h3>
        <p>Try this in search: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    </div>
    ''')

# -----------------------------
# Vulnerability 3: CSRF
# -----------------------------
@csrf_exempt
def transfer_money(request):
    if not request.user.is_authenticated:
        return redirect("/regular-login")

    if request.method == "POST":
        to_account = request.POST.get("to_account")
        amount = request.POST.get("amount")
        
        try:
            from_account = BankAccount.objects.get(user=request.user)
            to_account_obj = BankAccount.objects.get(account_number=to_account)
            
            # FIX: Convert amount to Decimal instead of float
            from decimal import Decimal
            transfer_amount = Decimal(amount)  # Convert to Decimal
            
            if from_account.balance >= transfer_amount:
                # FIX: Use Decimal arithmetic
                from_account.balance -= transfer_amount
                to_account_obj.balance += transfer_amount
                from_account.save()
                to_account_obj.save()

                Transaction.objects.create(
                    from_account=from_account,
                    to_account=to_account_obj,
                    amount=transfer_amount,  # Use Decimal here too
                    transaction_type="TRANSFER",
                    description=f"Transfer to {to_account}",
                )

                return HttpResponse(f'''
                <h3> Transfer Successful!</h3>
                <p>Transferred ${transfer_amount} to account {to_account}</p>
                <p>Your new balance: <strong>${from_account.balance}</strong></p>
                <a href="/transfer">Make another transfer</a> | <a href="/dashboard">Dashboard</a>
                ''')
            else:
                return HttpResponse(f'''
                <h3>Insufficient Funds!</h3>
                <p>Your balance: ${from_account.balance}</p>
                <p>Attempted transfer: ${transfer_amount}</p>
                <a href="/transfer">Try again</a>
                ''')

        except BankAccount.DoesNotExist:
            return HttpResponse("Account not found!")
        except ValueError:
            return HttpResponse("Invalid amount format!")
        except Exception as e:
            return HttpResponse(f"Error: {str(e)}")

    # GET request - show transfer form
    current_user = request.user.username if request.user.is_authenticated else "Unknown"
    return HttpResponse(f'''
    <h2>Transfer Money (CSRF Vulnerable)</h2>
    <p>Logged in as: <strong>{current_user}</strong></p>
    
    <form method="POST" action="/transfer">
        <!-- NO CSRF TOKEN - intentionally vulnerable -->
        To Account: <input type="text" name="to_account" placeholder="ACC000002" required><br><br>
        Amount: $<input type="number" name="amount" step="0.01" min="0.01" required><br><br>
        <button type="submit">Transfer Money</button>
    </form>

    <div style="margin-top: 30px; background: #ffe6e6; padding: 15px;">
        <h3>🚨 CSRF Attack Demo:</h3>
        <p>Test accounts:</p>
        <ul>
            <li><strong>ranim</strong>: ACC000001 </li>
            <li><strong>ghada</strong>: ACC000002 </li>
            <li><strong>amina</strong>: ACC000003 </li>
        </ul>
        
       
    <p><a href="/dashboard">← Back to Dashboard</a></p>
    ''')
# -----------------------------
# Vulnerability 4: IDOR
# -----------------------------
def account_info(request):
    if not request.user.is_authenticated:
        return redirect("/regular-login")

    account_id = request.GET.get("account_id", "")
    if account_id:
        try:
            account = BankAccount.objects.get(id=account_id)
            return HttpResponse(f'''
            <h2>👤 Account Information</h2>
            <p><strong>Account Owner:</strong> {account.user.username}</p>
            <p><strong>Account Number:</strong> {account.account_number}</p>
            <p><strong>Balance:</strong> ${account.balance}</p>
            <p><em>🚨 IDOR Vulnerability: You can view any account by changing account_id parameter</em></p>
            <a href="/account">← Back to my account</a>
            ''')
        except BankAccount.DoesNotExist:
            return HttpResponse("Account not found")

    # Show current user's account
    try:
        account = BankAccount.objects.get(user=request.user)
        return HttpResponse(f'''
        <h2>👤 My Account</h2>
        <p><strong>Account Number:</strong> {account.account_number}</p>
        <p><strong>Balance:</strong> ${account.balance}</p>

        <div style="background: #fff3cd; padding: 15px; margin: 20px 0;">
            <h3>🔓 IDOR Vulnerability Test:</h3>
            <p>Try viewing other users' accounts by changing the account_id:</p>
            <form>
                Account ID: <input type="number" name="account_id" placeholder="1, 2, 3..." required>
                <button type="submit">View Account</button>
            </form>
            <p><em>Try: account_id=1 (ranim), account_id=2 (ghada), account_id=3 (amina)</em></p>
        </div>
        
        <p><a href="/dashboard">← Back to Dashboard</a></p>
        ''')
    except BankAccount.DoesNotExist:
        return HttpResponse("No account found")
# -----------------------------
# Vulnerability 5: SSRF
# -----------------------------
# ----------------------------
#   INTERNAL MOCK ENDPOINT
# ----------------------------
def internal_mock(request):
    return JsonResponse({
        "secret": "SUCCESS_INTERNAL_ENDPOINT",
        "status": "ok"
    })

# ----------------------------
#   SSRF VULNERABLE ENDPOINT
# ----------------------------
def fetch_url(request):
    url = request.GET.get("url")

    if not url:
        return HttpResponse("""
            <h2>SSRF Demo</h2>
            <p>Enter a URL:</p>
            <form method='GET'>
                <input name='url' style='width:300px'>
                <button>Fetch</button>
            </form>
        """)

    try:
        r = requests.get(url, timeout=3)
        content = r.text[:2000]  # limiter pour éviter les gros dumps

        return HttpResponse(f"""
            <h2>Fetched URL Content</h2>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Status:</strong> {r.status_code}</p>

            <h3>Content Preview:</h3>
            <pre style="background:#eee;padding:10px;">{content}</pre>

            <p><a href="/fetch-url">Back</a></p>
        """)
    except Exception as e:
        return HttpResponse(f"<p>Error: {e}</p>")

def ssrf_page(request):
    return HttpResponse("""
        <h2>🧨 SSRF Test Interface</h2>
        <p>Enter any URL. The server will fetch it (vulnerable behavior).</p>
        
        <form method='GET' action='/fetch-url'>
            <input type='text' name='url' placeholder='http://127.0.0.1:8000/internal/mock' style='width:400px;'>
            <button type='submit'>Tester SSRF</button>
        </form>

        <p><a href='/'>← Retour Home</a></p>
    """)

# -----------------------------
# Logout
# -----------------------------
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('/')