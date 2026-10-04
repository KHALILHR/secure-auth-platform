"""Décorateurs d'accès aux routes (plan §5.3).

Analogie : le décorateur est le garde posté devant une porte précise. Il ne
connaît qu'une règle simple (« il faut un badge » ou « il faut un badge
d'administrateur »). Les règles plus fines sur les documents (habilitation,
liste d'accès) ne sont PAS ici : elles vivent dans policy.py et sont
vérifiées après le chargement du document, pas avant d'entrer dans la route.
"""
from functools import wraps

from flask import abort, g, redirect, request, url_for


def login_required(view):
    """Exige une session valide. Sinon, redirige vers la connexion."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def role_required(role: str):
    """Exige une session valide ET le rôle donné. Sinon, 403 (son existence n'est pas secrète)."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login", next=request.path))
            if g.user.role != role:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
