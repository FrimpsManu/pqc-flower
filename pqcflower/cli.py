"""Flower's commands with ML-DSA-65 farm login enabled (see pqc_login.py).

pqc-flower-superlink, pqc-flower-supernode and pqc-flwr take exactly the same arguments as
flower-superlink, flower-supernode and flwr. With PQC_SESSION_LOGIN=1 in the environment, farms
log in with ML-DSA once per session instead of on every request (see session_login.py).
"""

import os

from pqcflower import pqc_login, session_login


def _install() -> None:
    pqc_login.install()
    if os.environ.get("PQC_SESSION_LOGIN") == "1":
        session_login.install()


def superlink() -> None:
    _install()
    from flwr.superlink.cli import flower_superlink

    flower_superlink()


def supernode() -> None:
    _install()
    from flwr.supernode.cli import flower_supernode

    flower_supernode()


def flwr() -> None:
    _install()
    from flwr.cli.app import app

    app()
