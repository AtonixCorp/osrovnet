from django.db import models
from django.conf import settings


class SimulationJob(models.Model):
    TECHNIQUES = (
        ('grover', 'Grover Search Simulation'),
        ('qwalk', 'Quantum Walks'),
        ('fact_perm', 'Factorial Permutation Engine'),
        ('qdt', 'Quantum Decision Trees'),
        ('varc', 'Variational Circuits'),
        ('qbm', 'Quantum Boltzmann Machines'),
        ('qanneal', 'Quantum Annealing'),
        ('qentropy', 'Quantum Entropy Pool'),
        ('qgraph', 'Quantum-Inspired Graph Traversal'),
        ('qcollapse', 'Quantum State Collapse Simulation'),
    )

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    technique = models.CharField(max_length=64, choices=TECHNIQUES)
    name = models.CharField(max_length=150, blank=True)
    params = models.JSONField(default=dict, blank=True)
    result = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.owner} - {self.technique} ({self.name or self.id})"
