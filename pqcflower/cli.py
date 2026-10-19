"""Flower's commands with ML-DSA-65 farm login enabled (see pqc_login.py).

pqc-flower-superlink, pqc-flower-supernode and pqc-flwr take exactly the same arguments as
flower-superlink, flower-supernode and flwr.
"""

from pqcflower import pqc_login


def superlink() -> None:
    pqc_login.install()
    from flwr.superlink.cli import flower_superlink

    flower_superlink()


def supernode() -> None:
    pqc_login.install()
    from flwr.supernode.cli import flower_supernode

    flower_supernode()


def flwr() -> None:
    pqc_login.install()
    from flwr.cli.app import app

    app()
