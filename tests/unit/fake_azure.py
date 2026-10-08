"""An in-memory Azure network for the invariant tests (L24).

Just enough of azure-mgmt-network and azure-mgmt-compute for AzureConnector's
isolation paths, with Azure's semantics where they matter:
- a `get` returns a copy: changing it does nothing until `begin_create_or_update`;
- a missing resource raises ResourceNotFoundError (status 404); deleting a missing rule
  succeeds, as an ARM DELETE does;
- names are case-insensitive (ARM resource names are; assumed for rule names too);
- an NSG lists the NICs and subnets attached to it;
- two rules of one NSG can't share a priority in the same direction;
- a rule to Azure's DNS must have "*" as its source (InvalidDNSExfilSourceTag, measured);
- attaching an NSG that doesn't exist fails; a NIC can carry an Azure Policy that
  refuses any NSG other than the one the customer designed for it.

`open_flows` evaluates traffic as Azure does, independently of the connector's own
helpers: inbound crosses the subnet's NSG then the NIC's, outbound the reverse; in each
NSG the first rule that matches, by priority, decides; the default rules come last; no
NSG lets everything through. Azure's platform addresses (DNS, IMDS) are left out of the
probes: an NSG doesn't filter them without their service tags.

Faults: `chaos(op, phase, write)` is called before every call and after every write. It
can raise a transient error (429) or `Crash` — a BaseException, so it goes through the
connector's `except Exception` the way a killed process would.
"""
from __future__ import annotations

import copy
import ipaddress
from types import SimpleNamespace

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

SUB = "/subscriptions/s"


class Crash(BaseException):
    """The process dies here."""


def vm_id(rg: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"


def nic_id(rg: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{name}"


def nsg_id(rg: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}"


def subnet_id(rg: str, vnet: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{name}"


def key(resource_id: str) -> str:
    return (resource_id or "").rstrip("/").lower()


def _error(cls, status: int, message: str):
    exc = cls(message=message)
    exc.status_code = status
    return exc


def not_found(what: str):
    return _error(ResourceNotFoundError, 404, f"(ResourceNotFound) {what} was not found.")


def throttled(op: str):
    return _error(HttpResponseError, 429, f"(TooManyRequests) {op}: retry later")


_RULE_FIELDS = (
    "name", "priority", "direction", "access", "protocol",
    "source_address_prefix", "source_address_prefixes",
    "destination_address_prefix", "destination_address_prefixes",
    "source_port_range", "destination_port_range", "destination_port_ranges",
    "source_application_security_groups", "destination_application_security_groups",
    "description",
)


def _text(value) -> str:
    return str(getattr(value, "value", value) or "")


def _rule_record(rule) -> dict:
    rec = {f: copy.deepcopy(getattr(rule, f, None)) for f in _RULE_FIELDS}
    rec["direction"] = _text(rec["direction"])
    rec["access"] = _text(rec["access"])
    return rec


class _Done:
    def __init__(self, value=None):
        self._value = value

    def result(self, timeout=None):
        return self._value

    def done(self):
        return True


class FakeAzure:
    def __init__(self, chaos=None):
        self.chaos = chaos or (lambda op, phase, write: None)
        self.nsgs: dict[str, dict] = {}
        self.nics: dict[str, dict] = {}
        self.subnets: dict[str, dict] = {}
        self.vms: dict[str, dict] = {}
        self.network = SimpleNamespace(
            network_interfaces=_Nics(self), network_security_groups=_Nsgs(self),
            security_rules=_Rules(self), subnets=_Subnets(self))
        self.compute = SimpleNamespace(virtual_machines=_Vms(self))

    # ── building the customer's world ──────────────────────────────────────────

    def add_nsg(self, rg: str, name: str, rules=(), location="westeurope", tags=None) -> str:
        rid = nsg_id(rg, name)
        self.nsgs[key(rid)] = {"id": rid, "location": location, "tags": dict(tags or {}),
                               "rules": {}}
        for r in rules:
            self._put_rule(self.nsgs[key(rid)], _rule_record(r))
        return rid

    def add_subnet(self, rg: str, vnet: str, name: str, nsg: str | None) -> str:
        rid = subnet_id(rg, vnet, name)
        self.subnets[key(rid)] = {"id": rid, "nsg": nsg}
        return rid

    def add_vm(self, rg: str, name: str, nics: list[dict], os_type="Linux") -> str:
        """nics: [{rg, name, ips, subnet, nsg, policy}] — `policy`: an Azure Policy
        refusing any NSG on this NIC other than its own `nsg`."""
        ids = []
        for n in nics:
            rid = nic_id(n["rg"], n["name"])
            self.nics[key(rid)] = {"id": rid, "location": "westeurope", "nsg": n.get("nsg"),
                                   "design_nsg": n.get("nsg"), "ips": list(n["ips"]),
                                   "subnet": n["subnet"], "policy": bool(n.get("policy"))}
            ids.append(rid)
        rid = vm_id(rg, name)
        self.vms[key(rid)] = {"id": rid, "nics": ids, "os": os_type}
        return rid

    def snapshot(self) -> dict:
        return copy.deepcopy({"nsgs": self.nsgs, "nics": self.nics, "subnets": self.subnets,
                              "vms": self.vms})

    # ── plumbing ────────────────────────────────────────────────────────────────

    def call(self, op: str, write: bool, fn):
        self.chaos(op, "before", write)
        out = fn()
        if write:
            self.chaos(op, "after", write)
        return out

    def nsg(self, rg: str, name: str) -> dict:
        n = self.nsgs.get(key(nsg_id(rg, name)))
        if n is None:
            raise not_found(f"networkSecurityGroups/{name}")
        return n

    @staticmethod
    def _put_rule(nsg: dict, rec: dict) -> None:
        # Measured on the bench (2026-10-08): a rule to Azure's DNS must have "*" as its
        # source — it can't be scoped to one VM's addresses.
        dst = [rec.get("destination_address_prefix")] + list(rec.get("destination_address_prefixes") or [])
        src = [rec.get("source_address_prefix")] + list(rec.get("source_address_prefixes") or [])
        if any((d or "").lower() == "azureplatformdns" for d in dst) and [v for v in src if v] != ["*"]:
            raise _error(HttpResponseError, 400,
                         f"(InvalidDNSExfilSourceTag) {rec['name']}: DNS Exfiltration Tags must have "
                         '"*" as a sourceaddressPrefix')
        for other in nsg["rules"].values():
            if (other["name"].lower() != rec["name"].lower()
                    and other["direction"].lower() == rec["direction"].lower()
                    and other["priority"] == rec["priority"]):
                raise _error(HttpResponseError, 400,
                             f"(SecurityRuleConflict) {rec['name']} and {other['name']} share "
                             f"priority {rec['priority']} ({rec['direction']})")
        nsg["rules"][rec["name"].lower()] = rec

    def nsg_view(self, n: dict):
        return SimpleNamespace(
            id=n["id"], name=n["id"].rsplit("/", 1)[-1], location=n["location"],
            tags=dict(n["tags"]),
            security_rules=[SimpleNamespace(**r) for r in n["rules"].values()],
            network_interfaces=[SimpleNamespace(id=c["id"]) for c in self.nics.values()
                                if key(c["nsg"]) == key(n["id"])],
            subnets=[SimpleNamespace(id=s["id"]) for s in self.subnets.values()
                     if key(s["nsg"]) == key(n["id"])],
        )


class _Nics:
    def __init__(self, az: FakeAzure):
        self.az = az

    def _get(self, rg, name) -> dict:
        n = self.az.nics.get(key(nic_id(rg, name)))
        if n is None:
            raise not_found(f"networkInterfaces/{name}")
        return n

    def get(self, rg, name):
        def read():
            n = self._get(rg, name)
            return SimpleNamespace(
                id=n["id"], location=n["location"],
                network_security_group=SimpleNamespace(id=n["nsg"]) if n["nsg"] else None,
                ip_configurations=[SimpleNamespace(private_ip_address=ip,
                                                   subnet=SimpleNamespace(id=n["subnet"]))
                                   for ip in n["ips"]])
        return self.az.call("nic.get", False, read)

    def begin_create_or_update(self, rg, name, nic):
        def write():
            n = self._get(rg, name)
            new = getattr(getattr(nic, "network_security_group", None), "id", None)
            if new:
                if key(new) not in self.az.nsgs:
                    raise _error(HttpResponseError, 400,
                                 f"(InvalidResourceReference) {new} referenced by {name} was not found.")
                if n["policy"] and key(new) != key(n["design_nsg"]):
                    raise _error(HttpResponseError, 403,
                                 f"(RequestDisallowedByPolicy) NSG on {name} not allowed")
            n["nsg"] = self.az.nsgs[key(new)]["id"] if new else None
            return _Done()
        return self.az.call("nic.write", True, write)

    def list_all(self):
        return self.az.call("nic.list", False, lambda: [self.get(*_rg_name(n["id"]))
                                                        for n in self.az.nics.values()])


class _Nsgs:
    def __init__(self, az: FakeAzure):
        self.az = az

    def get(self, rg, name):
        return self.az.call("nsg.get", False, lambda: self.az.nsg_view(self.az.nsg(rg, name)))

    def begin_create_or_update(self, rg, name, model):
        def write():
            rid = nsg_id(rg, name)
            n = {"id": rid, "location": getattr(model, "location", None) or "westeurope",
                 "tags": dict(getattr(model, "tags", None) or {}), "rules": {}}
            for r in getattr(model, "security_rules", None) or []:
                FakeAzure._put_rule(n, _rule_record(r))
            self.az.nsgs[key(rid)] = n
            return _Done(self.az.nsg_view(n))
        return self.az.call("nsg.write", True, write)

    def update_tags(self, rg, name, tags_object):
        def write():
            n = self.az.nsg(rg, name)
            n["tags"] = dict(getattr(tags_object, "tags", None) or {})
            return self.az.nsg_view(n)
        return self.az.call("nsg.tags", True, write)


class _Rules:
    def __init__(self, az: FakeAzure):
        self.az = az

    def list(self, rg, nsg_name):
        return self.az.call("rule.list", False, lambda: [
            SimpleNamespace(**r) for r in self.az.nsg(rg, nsg_name)["rules"].values()])

    def get(self, rg, nsg_name, name):
        def read():
            r = self.az.nsg(rg, nsg_name)["rules"].get(name.lower())
            if r is None:
                raise not_found(f"securityRules/{name}")
            return SimpleNamespace(**r)
        return self.az.call("rule.get", False, read)

    def begin_create_or_update(self, rg, nsg_name, name, rule):
        def write():
            rec = _rule_record(rule)
            rec["name"] = name
            FakeAzure._put_rule(self.az.nsg(rg, nsg_name), rec)
            return _Done(SimpleNamespace(**rec))
        return self.az.call("rule.write", True, write)

    def begin_delete(self, rg, nsg_name, name):
        def write():
            self.az.nsg(rg, nsg_name)["rules"].pop(name.lower(), None)
            return _Done()
        return self.az.call("rule.delete", True, write)


class _Subnets:
    def __init__(self, az: FakeAzure):
        self.az = az

    def get(self, rg, vnet, name):
        def read():
            s = self.az.subnets.get(key(subnet_id(rg, vnet, name)))
            if s is None:
                raise not_found(f"subnets/{name}")
            return SimpleNamespace(id=s["id"], network_security_group=(
                SimpleNamespace(id=s["nsg"]) if s["nsg"] else None))
        return self.az.call("subnet.get", False, read)


class _Vms:
    def __init__(self, az: FakeAzure):
        self.az = az

    def _get(self, rg, name) -> dict:
        v = self.az.vms.get(key(vm_id(rg, name)))
        if v is None:
            raise not_found(f"virtualMachines/{name}")
        return v

    def get(self, rg, name):
        def read():
            v = self._get(rg, name)
            return SimpleNamespace(
                id=v["id"],
                network_profile=SimpleNamespace(network_interfaces=[
                    SimpleNamespace(id=n, primary=i == 0) for i, n in enumerate(v["nics"])]),
                storage_profile=SimpleNamespace(os_disk=SimpleNamespace(os_type=v["os"])))
        return self.az.call("vm.get", False, read)

    def begin_run_command(self, rg, name, command):
        def run():
            self._get(rg, name)
            return _Done(SimpleNamespace(value=[SimpleNamespace(
                message="Enable succeeded:\n[stdout]\nglorfindel-drain-remaining=0\n[stderr]\n")]))
        return self.az.call("vm.run_command", True, run)


def _rg_name(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1], parts[-1]


# ── traffic, evaluated as Azure does ─────────────────────────────────────────────

INTERNET = "203.0.113.7"          # documentation range (RFC 5737), outside the 3 private blocks
LATERAL = "10.9.9.9"
AZURE_DNS = "168.63.129.16"
AZURE_IMDS = "169.254.169.254"
# (direction, peer, port): an attacker on the internet (SSH, HTTPS), a neighbour in the
# VNet (lateral movement), the VM calling out (exfiltration, C2, lateral), and Azure's
# DNS (a tunnel) and IMDS (managed-identity tokens).
PROBES = (("in", INTERNET, 22), ("in", INTERNET, 443), ("in", LATERAL, 22),
          ("out", INTERNET, 443), ("out", LATERAL, 445),
          ("out", AZURE_DNS, 53), ("out", AZURE_IMDS, 80))
# Platform addresses: no rule filters them unless it names their service tag — a
# deny-all, the default rules included, lets them through (measured on the bench).
_PLATFORM = {AZURE_DNS: "azureplatformdns", AZURE_IMDS: "azureplatformimds"}

_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_DEFAULTS = {
    "in": [(65000, "allow", "VirtualNetwork", "VirtualNetwork", "*"),
           (65001, "allow", "AzureLoadBalancer", "*", "*"),
           (65500, "deny", "*", "*", "*")],
    "out": [(65000, "allow", "VirtualNetwork", "VirtualNetwork", "*"),
            (65001, "allow", "*", "Internet", "*"),
            (65500, "deny", "*", "*", "*")],
}


def _private(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in n for n in _PRIVATE)


def _covers(prefix: str, ip: str) -> bool:
    p = (prefix or "").strip()
    low = p.lower()
    if low in ("*", "any"):
        return True
    if low == "virtualnetwork":
        return _private(ip)
    if low == "internet":
        return not _private(ip)
    if low.startswith("azure"):            # platform and service tags: never these probes
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(p, strict=False)
    except ValueError:
        return False


def _side(rule: dict, side: str, ip: str) -> bool:
    values = [rule.get(f"{side}_address_prefix")] + list(rule.get(f"{side}_address_prefixes") or [])
    values = [v for v in values if v]
    return any(_covers(v, ip) for v in values) if values else True


def _port(rule: dict, port: int) -> bool:
    ranges = [rule.get("destination_port_range")] + list(rule.get("destination_port_ranges") or [])
    for pr in (str(r).strip() for r in ranges if r):
        if pr in ("*", "Any", "any"):
            return True
        lo, _, hi = pr.partition("-")
        if int(lo) <= port <= int(hi or lo):
            return True
    return False


def _names_tag(rule: dict, tag: str) -> bool:
    values = [rule.get("destination_address_prefix")] + list(rule.get("destination_address_prefixes") or [])
    return any((v or "").strip().lower() == tag for v in values)


def _nsg_allows(nsg: dict, direction: str, src: str, dst: str, port: int) -> bool:
    rules = [(r["priority"], r["access"].lower(), r) for r in nsg["rules"].values()
             if r["direction"].lower() == ("inbound" if direction == "in" else "outbound")]
    if direction == "out" and dst in _PLATFORM:
        tag = _PLATFORM[dst]
        for _, access, r in sorted(rules, key=lambda x: x[0]):
            if _names_tag(r, tag) and _side(r, "source", src) and _port(r, port):
                return access == "allow"
        return True
    rules += [(p, a, {"source_address_prefix": s, "destination_address_prefix": d,
                      "destination_port_range": pr})
              for p, a, s, d, pr in _DEFAULTS[direction]]
    for _, access, r in sorted(rules, key=lambda x: x[0]):
        if _side(r, "source", src) and _side(r, "destination", dst) and _port(r, port):
            return access == "allow"
    return False


def open_flows(world: dict, vm: str) -> frozenset:
    """The probes that get through, for every IP of every NIC of the VM."""
    v = world["vms"][key(vm)]
    out = set()
    for n_id in v["nics"]:
        nic = world["nics"][key(n_id)]
        sub = world["subnets"][key(nic["subnet"])]
        chain = [sub["nsg"], nic["nsg"]]
        for direction, peer, port in PROBES:
            for ip in nic["ips"]:
                src, dst = (peer, ip) if direction == "in" else (ip, peer)
                order = chain if direction == "in" else list(reversed(chain))
                if all(_nsg_allows(world["nsgs"][key(g)], direction, src, dst, port)
                       for g in order if g):
                    out.add((nic["id"].rsplit("/", 1)[-1], ip, direction, peer, port))
    return frozenset(out)
