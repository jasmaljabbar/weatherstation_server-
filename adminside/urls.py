from django.urls import path
from .views import Dashboard,Block_user

urlpatterns = [
    path("dashboard/", Dashboard.as_view(), name="dashboard"),
    path("user_action/", Block_user.as_view(), name="user_action"),
 
]