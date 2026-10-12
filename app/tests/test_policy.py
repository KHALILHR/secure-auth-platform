"""Règles d'autorisation (cahier des charges, section 6.2) : une vérification par règle."""
from datetime import timedelta

from helpers import make_user, new_document

from secureauth.documents import service as documents
from secureauth.extensions import db
from secureauth.models import utcnow
from secureauth.security import policy


def _doc(owner, level):
    return new_document(owner, level=level)


# --- can_read ---------------------------------------------------------------------

def test_owner_reads_own_document(app):
    alice = make_user("alice", clearance=2)
    assert policy.can_read(alice, _doc(alice, 2))


def test_no_read_up(app):
    """Bell-LaPadula : pas de lecture vers le haut, même avec une ligne d'accès."""
    alice = make_user("alice", clearance=3)
    bob = make_user("bob", clearance=2)
    doc = _doc(alice, 3)
    db.session.add(policy.DocumentAccess(document_id=doc.id, user_id=bob.id, granted_by=alice.id))
    db.session.commit()
    assert not policy.can_read(bob, doc)


def test_need_to_know(app):
    """Habilitation suffisante mais hors liste d'accès : refusé."""
    alice = make_user("alice", clearance=2)
    bob = make_user("bob", clearance=3)
    assert not policy.can_read(bob, _doc(alice, 1))


def test_read_requires_active_and_unlocked_account(app):
    alice = make_user("alice", clearance=1)
    doc = _doc(alice, 1)
    assert policy.can_read(alice, doc)
    alice.is_active = False
    assert not policy.can_read(alice, doc)
    alice.is_active = True
    alice.locked_until = utcnow() + timedelta(minutes=5)
    assert not policy.can_read(alice, doc)


def test_admin_cannot_read_by_role(app):
    alice = make_user("alice", clearance=2)
    admin = make_user("root", role="admin", clearance=3)
    assert not policy.can_read(admin, _doc(alice, 0))


def test_readable_documents_filters_every_row_through_can_read(app):
    alice = make_user("alice", clearance=3)
    bob = make_user("bob", clearance=2)
    ts = _doc(alice, 3)
    sec = _doc(alice, 2)
    documents.grant_access(alice, bob, sec)
    db.session.add(policy.DocumentAccess(document_id=ts.id, user_id=bob.id, granted_by=alice.id))  # ligne forcée
    db.session.commit()
    assert [d.id for d in policy.readable_documents(bob)] == [sec.id]


# --- can_create -----------------------------------------------------------------------

def test_can_create_up_to_clearance_only(app):
    bob = make_user("bob", clearance=2)
    assert all(policy.can_create(bob, lvl) for lvl in (0, 1, 2))
    assert not policy.can_create(bob, 3)
    assert not policy.can_create(bob, -1)
    bob.is_active = False
    assert not policy.can_create(bob, 0)


# --- can_grant / can_revoke ------------------------------------------------------------

def test_grant_rules(app):
    alice = make_user("alice", clearance=2)
    bob = make_user("bob", clearance=2)
    low = make_user("low", clearance=1)
    gone = make_user("gone", clearance=2, active=False)
    eve = make_user("eve", clearance=3)
    admin = make_user("root", role="admin", clearance=0)
    doc = _doc(alice, 2)

    assert policy.can_grant(alice, bob, doc)               # propriétaire vers agent habilité
    assert policy.can_grant(admin, bob, doc)               # l'administrateur gère les accès
    assert not policy.can_grant(alice, low, doc)           # habilitation insuffisante
    assert not policy.can_grant(alice, gone, doc)          # compte désactivé
    assert not policy.can_grant(eve, bob, doc)             # ni propriétaire ni admin
    assert not policy.can_grant(admin, admin, doc)         # un admin ne s'attribue rien


def test_revoke_rules(app):
    alice = make_user("alice", clearance=2)
    bob = make_user("bob", clearance=2)
    eve = make_user("eve", clearance=2)
    admin = make_user("root", role="admin")
    doc = _doc(alice, 2)
    assert policy.can_revoke(alice, bob, doc)
    assert policy.can_revoke(admin, bob, doc)
    assert not policy.can_revoke(alice, alice, doc)        # le propriétaire garde son accès
    assert not policy.can_revoke(admin, alice, doc)
    assert not policy.can_revoke(eve, bob, doc)


# --- can_admin_modify / métadonnées --------------------------------------------------------

def test_admin_modify_rules(app):
    admin = make_user("root", role="admin")
    other = make_user("alice")
    agent = make_user("bob")
    assert policy.can_admin_modify(admin, other)
    assert not policy.can_admin_modify(admin, admin)       # jamais ses propres droits
    assert not policy.can_admin_modify(agent, other)       # un agent n'administre rien


def test_metadata_is_for_admins_only(app):
    assert policy.can_view_metadata(make_user("root", role="admin"))
    assert not policy.can_view_metadata(make_user("alice"))


def test_list_access_is_for_owner_or_admin(app):
    alice = make_user("alice", clearance=1)
    bob = make_user("bob", clearance=1)
    admin = make_user("root", role="admin")
    doc = _doc(alice, 1)
    assert policy.can_list_access(alice, doc) and policy.can_list_access(admin, doc)
    assert not policy.can_list_access(bob, doc)
