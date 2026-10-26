"""AwsConnector: the AWS implementation of CloudConnector (MC1), written against an
injected EC2 client (client.Ec2Client) — the simulated world of the invariants
(tests/unit/fake_aws.py) until MC2 brings boto3 and an AWS bench.

The guards Azure's writes go through, transposed: the account-and-region guard (an ARN of
another account or region is refused, H14 — I12), and the instance's lock on writes.

The provider-neutral core (state, locks) is read through its modules at call time
(`_state._save_isolation_state`, `_locks._vm_lock`): a test's patch through
`glorfindel.actions` sets the name in those modules, and so reaches this adapter too.
This adapter is not part of that façade (`glorfindel/actions.py`): it holds Azure's names.
"""
from __future__ import annotations

import functools

from glorfindel.providers.aws.blocks import BlockMixin
from glorfindel.providers.aws.capabilities import CAPABILITIES as AWS_CAPABILITIES
from glorfindel.providers.aws.client import parse_instance_arn
from glorfindel.providers.aws.isolation import IsolationMixin
from glorfindel.providers.aws.network import NetworkMixin
from glorfindel.providers.aws.quarantine import QuarantineMixin
from glorfindel.providers.interface import CloudConnector
from glorfindel.response import locks as _locks
from glorfindel.response.policy import WrongSubscriptionError

_NOT_IN_MC1 = "pas d'instantané ni de restauration sur AWS en MC1 (restore_point non déclaré)"


class WrongAccountError(WrongSubscriptionError):
    """An instance of another AWS account or region: the client acts in one of each."""


class AwsConnector(NetworkMixin, QuarantineMixin, IsolationMixin, BlockMixin, CloudConnector):
    """AWS implementation of CloudConnector — simulated (MC1).

    ec2: an EC2 client of `region` in `account` (boto3's, in MC2; the fake's, today).
    Resource ids are instance ARNs."""

    CAPABILITIES = AWS_CAPABILITIES

    def __init__(self, ec2=None, account: str = "", region: str = "", dry_run: bool = False,
                 read_only: bool | None = None):
        self._ec2 = ec2
        self.account, self.region = account, region
        self.dry_run = dry_run
        if read_only is None:
            from glorfindel.config import read_only_requested
            read_only = read_only_requested()
        self.read_only = read_only

    def permission_mode(self) -> str:
        return "read_only" if self.read_only else "read_write"

    def _guard_write(self, action: str) -> None:
        if self.read_only:
            raise PermissionError(
                f"Action '{action}' impossible : credentials lecture seule (GLORFINDEL_READ_ONLY). "
                "Glorfindel détecte et recommande mais ne peut pas agir.")
        if self._ec2 is None:
            raise RuntimeError("aucun client EC2 : l'adaptateur AWS est simulé (MC1), boto3 vient avec MC2")

    def recent_changes(self, nic_id: str) -> list[str]:
        """Who wrote the ENI lately — CloudTrail, in MC2. Nothing to say today."""
        return []

    def snapshot(self, resource_id: str, vault: str = "", wait: bool = True, vault_rg: str = "") -> str:
        raise NotImplementedError(_NOT_IN_MC1)

    def verify_snapshot(self, snap_id: str) -> dict:
        raise NotImplementedError(_NOT_IN_MC1)

    def restore_from_backup(self, resource_id: str, vault: str = "", before_attack_time: str | None = None,
                            wait: bool = True, staging_storage: str = "", vault_rg: str = "") -> dict:
        raise NotImplementedError(_NOT_IN_MC1)

    def restore_job_status(self, vault: str, vault_rg: str, job_name: str) -> str:
        raise NotImplementedError(_NOT_IN_MC1)


def _resource_id(args, kwargs) -> str:
    return kwargs.get("resource_id") or next(
        (a for a in args if isinstance(a, str) and a.startswith("arn:")), "") or next(
        (a for a in reversed(args) if isinstance(a, str) and "/" in a), "")


def _same_account(method):
    """Refuse to act on (or vouch for) an instance of another account or region, or an id
    that is no instance ARN — the action would land elsewhere, or nowhere (I12)."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.dry_run:
            rid = _resource_id(args, kwargs)
            try:
                region, account, _ = parse_instance_arn(rid)
            except ValueError as exc:
                raise WrongAccountError(str(exc)) from None
            if (self.account and account != self.account) or (self.region and region != self.region):
                raise WrongAccountError(
                    f"{rid} est dans le compte {account}, région {region} ; Glorfindel agit dans "
                    f"{self.account}, {self.region} : action refusée (elle viserait une autre instance, ou aucune).")
        return method(self, *args, **kwargs)
    return wrapper


def _one_writer(method):
    """Hold the instance's lock for the whole write (as Azure's _vm_lock)."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        rid = _resource_id(args, kwargs)
        if self.dry_run or not rid:
            return method(self, *args, **kwargs)
        with _locks._vm_lock(rid.rstrip("/").rsplit("/", 1)[-1]):
            return method(self, *args, **kwargs)
    return wrapper


for _name in ("isolate_vm", "release_isolation", "block_suspicious_ip", "unblock_ip"):
    setattr(AwsConnector, _name, _one_writer(getattr(AwsConnector, _name)))
for _name in ("isolate_vm", "release_isolation", "verify_isolation", "verify_release",
              "block_suspicious_ip", "unblock_ip", "verify_block_ip"):
    setattr(AwsConnector, _name, _same_account(getattr(AwsConnector, _name)))
