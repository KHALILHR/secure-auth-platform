from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
server_session = Session()
csrf = CSRFProtect()
# Limitation de débit par adresse IP réelle (ProxyFix la reconstitue derrière Nginx).
# Les seuils et le stockage (Redis) viennent de la configuration.
limiter = Limiter(key_func=get_remote_address)
