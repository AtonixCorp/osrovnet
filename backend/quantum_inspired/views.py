from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .services import (
    grover_search_simulation,
    quantum_walks_simulation,
    factorial_permutation_engine,
    quantum_decision_trees,
    variational_circuits_simulation,
    quantum_boltzmann_clustering,
    quantum_annealing_simulation,
    quantum_entropy_pool,
    quantum_inspired_graph_traversal,
    quantum_state_collapse_simulation,
)
from .models import SimulationJob
from .serializers import SimulationJobSerializer


TECHNIQUE_CATALOG = {
    'grover': 'Grover Search Simulation (classical approximation)',
    'qwalk': 'Quantum Walks (propagation modeling)',
    'fact_perm': 'Factorial Permutation Engine (path enumeration)',
    'qdt': 'Quantum Decision Trees (behavioral analytics)',
    'varc': 'Variational Circuits (pattern recognition)',
    'qbm': 'Quantum Boltzmann Machines (threat clustering)',
    'qanneal': 'Quantum Annealing (attack surface optimization)',
    'qentropy': 'Quantum Entropy Pool (entropy expansion)',
    'qgraph': 'Quantum-Inspired Graph Traversal (lateral movement detection)',
    'qcollapse': 'Quantum State Collapse Simulation (threat resolution)',
}


class TechniqueListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response([{'key': k, 'description': v} for k, v in TECHNIQUE_CATALOG.items()])


class RunSimulationView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        technique = request.data.get('technique')
        params = request.data.get('params', {})
        if technique not in TECHNIQUE_CATALOG:
            return Response({'detail': 'unknown technique'}, status=status.HTTP_400_BAD_REQUEST)

        job = SimulationJob.objects.create(owner=request.user, technique=technique, params=params)

        result = {}
        try:
            if technique == 'grover':
                dataset = params.get('dataset', [])
                result = grover_search_simulation(dataset, lambda v: v in params.get('matches', []))
            elif technique == 'qwalk':
                result = quantum_walks_simulation(params.get('edges', []), params.get('source', 0), params.get('depth', 3))
            elif technique == 'fact_perm':
                result = factorial_permutation_engine(params.get('items', []), params.get('limit', 100))
            elif technique == 'qdt':
                result = quantum_decision_trees(params.get('data', []), params.get('max_depth', 3))
            elif technique == 'varc':
                result = variational_circuits_simulation(params.get('features', []), params.get('epochs', 20))
            elif technique == 'qbm':
                result = quantum_boltzmann_clustering(params.get('points', []), params.get('k', 3), params.get('iterations', 10))
            elif technique == 'qanneal':
                states = params.get('states', [])
                result = quantum_annealing_simulation(states, lambda x: params.get('energy_map', {}).get(str(x), 1e9), params.get('steps', 100))
            elif technique == 'qentropy':
                seed = bytes(params.get('seed', ''), 'utf-8')
                out = quantum_entropy_pool(seed, params.get('extra', 32))
                import base64
                result = {'entropy_b64': base64.b64encode(out).decode('ascii')}
            elif technique == 'qgraph':
                result = quantum_inspired_graph_traversal(params.get('edges', []), params.get('start', 0), params.get('depth', 4))
            elif technique == 'qcollapse':
                result = quantum_state_collapse_simulation(params.get('candidates', []), params.get('scores', []))
        except Exception as e:
            return Response({'detail': f'error running simulation: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        job.result = result
        job.save()

        serializer = SimulationJobSerializer(job)
        return Response(serializer.data)
