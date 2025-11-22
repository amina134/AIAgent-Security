from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('banking_env.urls')),

    # path('security_agent/', include('security_agent.urls')),
      
]
