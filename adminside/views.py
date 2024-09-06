from rest_framework.views import APIView
from account.models import UserData
from .serializers import UserDataSerializer
from rest_framework.response import Response
from rest_framework import status


class Dashboard(APIView):

    def get(self, request):
        users = UserData.objects.filter(is_superuser=False)
        serializer = UserDataSerializer(users, many=True)
        return Response(serializer.data)
    


class Block_user(APIView):

    def post(self, request):
        user_id = request.data.get("id")
        try:
            user = UserData.objects.get(id=user_id)
            user.is_active = not user.is_active
            user.save()
            return Response({"success": "User action completed", "is_active": user.is_active}, status=status.HTTP_200_OK)
        except UserData.DoesNotExist:
            return Response(
                {"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND
            )
