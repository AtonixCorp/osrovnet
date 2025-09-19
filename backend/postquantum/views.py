from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from .services import list_supported_algorithms, generate_keypair
from .serializers import AlgorithmListSerializer, PQCKeySerializer
from .models import PQCKey


class AlgorithmListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        algos = list_supported_algorithms()
        data = [{'name': k, 'description': v} for k, v in algos.items()]
        serializer = AlgorithmListSerializer(data, many=True)
        return Response(serializer.data)


class GenerateKeyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        algorithm = request.data.get('algorithm')
        name = request.data.get('name', f'{algorithm}-key')
        if not algorithm:
            return Response({'detail': 'algorithm is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            pub, priv = generate_keypair(algorithm)
        except NotImplementedError as e:
            return Response({'detail': str(e)}, status=status.HTTP_501_NOT_IMPLEMENTED)
        except Exception as e:
            return Response({'detail': f'error generating key: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Persist metadata and public key only
        record = PQCKey.objects.create(
            owner=request.user,
            name=name,
            algorithm=algorithm,
            public_key=pub,
            private_key_retention='none',
        )
        serializer = PQCKeySerializer(record)
        # Return base64 encoded keys to the client for immediate download
        import base64
        return Response({
            'record': serializer.data,
            'public_key_b64': base64.b64encode(pub).decode('ascii'),
            'private_key_b64': base64.b64encode(priv).decode('ascii'),
        })
