"""How a grant is read. `auth.py` depends on this file, so a change here
changes whether the requirement holds without touching its subject."""


def grant_allows(grant):
    return grant == "allow"
