"""The subject of `custody-authorization`: an owner is always authorized,
and anyone else only under an allowing grant."""

from src.parser import grant_allows


def authorize(role, grant):
    return role == "owner" or grant_allows(grant)
