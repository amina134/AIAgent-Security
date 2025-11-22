from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("vulnerable-login", views.vulnerable_sql_login, name="vulnerable_login"),
    path("regular-login", views.regular_login, name="regular_login"),
    path("dashboard", views.dashboard, name="dashboard"),
    path("transfer", views.transfer_money, name="transfer"),
    path("account", views.account_info, name="account"),
    #path("api/fetch-external", views.api_fetch_external_data, name="api_fetch_external"),
    path('ssrf', views.ssrf_page, name='ssrf'),
    path('fetch-url', views.fetch_url, name='fetch_url'),
    path('internal/mock', views.internal_mock, name='internal_mock'),
    path("logout", views.logout_view, name="logout"),
]