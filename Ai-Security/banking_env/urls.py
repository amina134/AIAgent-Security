from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),

    # Vulnerable login (SQL Injection test)
    path("vulnerable-login", views.vulnerable_sql_login, name="vulnerable_login"),

    # Safe login
    path("regular-login", views.regular_login, name="regular_login"),

    # User dashboard
    path("dashboard", views.dashboard, name="dashboard"),

    # Fake money transfer csrf)
    path("transfer", views.transfer_money, name="transfer"),

    # Account info page (IDOR testing)
    path("account", views.account_info, name="account"),

    # Logout
    path("logout", views.logout_view, name="logout"),
]
