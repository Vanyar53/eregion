"""An in-memory AWS network (EC2, VPC) for the invariant tests on AWS (MC1).

The calls the AWS adapter makes (glorfindel/providers/aws/client.py), with boto3's names,
arguments and answers, and AWS's semantics where they matter. Each is a HYPOTHESIS read in
AWS's documentation, numbered in docs/design/monde-aws.md, to be measured on the AWS bench
(MC2) — nothing here is measured:
- H1  a security group (SG) only allows; the groups of an ENI are a union; stateful;
- H2  an ENI carries 1 to 5 SGs of its own VPC: [] or a 6th is refused, an SG of another
      VPC is not found;
- H3  a new SG has one egress rule (allow all) and no ingress;
- H4  an SG's name is unique in its VPC; `default` exists; an SG carried by an ENI can't be
      deleted (DependencyViolation); a new SG gets a new id;
- H5  a network ACL is stateless; entries 1–32766, the lowest that matches decides, `*`
      (32767) denies; an inbound entry names the source only, an outbound one the
      destination only; 20 entries per direction; a number taken is refused; deleting a
      missing entry fails;
- H6  neither SGs nor ACLs filter Amazon's DNS resolver and IMDS;
- H7  create_tags merges by key, delete_tags removes the keys named;
- H8  errors are botocore's ClientError shape (`response["Error"]["Code"]`, the status);
- H9  authorize/revoke are all or nothing: a duplicate or a missing rule fails the call;
- H12 a write has taken effect when it returns (no eventual consistency modelled);
- H13 a policy (SCP, IAM condition) can refuse the group change of one ENI;
- H16 a terminated instance is still described a while, without network interfaces.

`open_flows` evaluates traffic as AWS does, independently of the adapter: a probe gets
through when one of the ENI's groups allows it (stateful: the request only) and the
subnet's ACL allows the request AND its answer (stateless: the answer is a flow of its
own, to or from an ephemeral port). Amazon's DNS and IMDS always get through (H6).

Faults: `chaos(op, phase, write)` before every call and after every write, as in
fake_azure: a throttled call (RequestLimitExceeded) or `Crash`.
"""
from __future__ import annotations

import copy
import ipaddress

from .fake_azure import Crash  # noqa: F401  (one Crash for both worlds)

ACCOUNT, REGION = "111122223333", "eu-west-3"    # AWS's documentation account: no real one


def arn(instance_id: str, account: str = ACCOUNT, region: str = REGION) -> str:
    return f"arn:aws:ec2:{region}:{account}:instance/{instance_id}"


class ClientError(Exception):
    """botocore.exceptions.ClientError's shape (H8), without botocore."""

    def __init__(self, code: str, message: str, status: int = 400, op: str = ""):
        super().__init__(f"An error occurred ({code}) when calling the {op} operation: {message}")
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}
        self.operation_name = op


def throttled(op: str) -> ClientError:
    return ClientError("RequestLimitExceeded", "Request limit exceeded.", 503, op)


_ACL_MAX = 20                  # H5: entries per direction (the `*` entry aside)
_SG_MAX = 5                    # H2


def _proto(value) -> str:
    """'-1', 'tcp', 'udp' — whatever the caller wrote ('6', 'TCP', -1)."""
    v = str(value).lower()
    return {"6": "tcp", "17": "udp", "all": "-1"}.get(v, v)


def _sg_rules(perms) -> list[dict]:
    """IpPermissions → one rule per source (a CIDR or a group)."""
    out = []
    for p in perms or []:
        base = {"proto": _proto(p.get("IpProtocol", "-1")), "from": p.get("FromPort"), "to": p.get("ToPort")}
        if base["proto"] == "-1":
            base["from"] = base["to"] = None
        for r in p.get("IpRanges") or []:
            out.append({**base, "cidr": r["CidrIp"], "group": None})
        for g in p.get("UserIdGroupPairs") or []:
            out.append({**base, "cidr": None, "group": g["GroupId"]})
    return out


def _sg_perm(rule: dict) -> dict:
    p = {"IpProtocol": rule["proto"], "IpRanges": [], "UserIdGroupPairs": []}
    if rule["from"] is not None:
        p["FromPort"], p["ToPort"] = rule["from"], rule["to"]
    if rule["cidr"]:
        p["IpRanges"].append({"CidrIp": rule["cidr"]})
    else:
        p["UserIdGroupPairs"].append({"GroupId": rule["group"]})
    return p


def sg_rule(proto="-1", port=None, cidr=None, group=None, to=None) -> dict:
    """A rule as the test writes it (port: one port, or a range with `to`)."""
    proto = _proto(proto)
    lo = None if proto == "-1" else port
    return {"proto": proto, "from": lo, "to": None if proto == "-1" else (to or port),
            "cidr": cidr, "group": group}


def acl_entry(number: int, egress: bool, action: str, cidr: str, proto="-1", port=None, to=None) -> dict:
    proto = {"tcp": "6", "udp": "17"}.get(str(proto), str(proto))
    return {"number": number, "egress": egress, "action": action, "proto": proto, "cidr": cidr,
            "from": None if proto == "-1" else port, "to": None if proto == "-1" else (to or port)}


class FakeAws:
    def __init__(self, chaos=None):
        self.chaos = chaos or (lambda op, phase, write: None)
        self.vpcs: dict[str, dict] = {}
        self.subnets: dict[str, dict] = {}
        self.sgs: dict[str, dict] = {}
        self.acls: dict[str, dict] = {}
        self.enis: dict[str, dict] = {}
        self.instances: dict[str, dict] = {}
        self.write_denied = False
        # Every write through the API (Glorfindel's: the test plays everyone else on the
        # dicts), and what it created: ACL entries (acl, egress, number) → their content.
        self.journal: list[dict] = []
        self.authored: dict[tuple, dict] = {}
        self._n = 0

    # ── building the customer's world ──────────────────────────────────────────

    def add_vpc(self, vpc: str, cidr: str) -> None:
        self.vpcs[vpc] = {"id": vpc, "cidr": cidr}
        self.add_sg(vpc, f"sg-default-{vpc}", "default",
                    ingress=[sg_rule(group=f"sg-default-{vpc}")], egress=[sg_rule(cidr="0.0.0.0/0")])
        self.add_acl(vpc, f"acl-default-{vpc}", [acl_entry(100, False, "allow", "0.0.0.0/0"),
                                                  acl_entry(100, True, "allow", "0.0.0.0/0")], default=True)

    def add_sg(self, vpc: str, sg_id: str, name: str, ingress=(), egress=(), tags=None) -> str:
        self.sgs[sg_id] = {"id": sg_id, "name": name, "vpc": vpc, "tags": dict(tags or {}),
                           "ingress": [dict(r) for r in ingress], "egress": [dict(r) for r in egress]}
        return sg_id

    def add_acl(self, vpc: str, acl_id: str, entries=(), default=False) -> str:
        self.acls[acl_id] = {"id": acl_id, "vpc": vpc, "default": default,
                             "entries": {(e["egress"], e["number"]): dict(e) for e in entries}}
        return acl_id

    def add_subnet(self, vpc: str, subnet: str, cidr: str, acl: str) -> str:
        self.subnets[subnet] = {"id": subnet, "vpc": vpc, "cidr": cidr, "acl": acl}
        return subnet

    def add_instance(self, iid: str, enis: list[dict], platform: str = "linux") -> str:
        """enis: [{id, subnet, ips, groups, policy}] — `policy`: an SCP refusing any change
        of this ENI's groups (H13)."""
        for e in enis:
            vpc = self.subnets[e["subnet"]]["vpc"]
            groups = list(e["groups"]) or [f"sg-default-{vpc}"]
            self.enis[e["id"]] = {"id": e["id"], "subnet": e["subnet"], "vpc": vpc, "ips": list(e["ips"]),
                                  "groups": groups, "design_groups": list(groups),
                                  "policy": bool(e.get("policy")), "instance": iid}
        self.instances[iid] = {"id": iid, "enis": [e["id"] for e in enis], "platform": platform}
        return iid

    def delete_sg(self, sg_id: str) -> bool:
        """The customer deletes an SG — refused while an ENI carries it, and for `default` (H4)."""
        sg = self.sgs.get(sg_id)
        if sg is None or sg["name"] == "default" or any(sg_id in e["groups"] for e in self.enis.values()):
            return False
        del self.sgs[sg_id]
        return True

    def default_sg(self, vpc: str) -> str:
        return f"sg-default-{vpc}"

    def snapshot(self) -> dict:
        return copy.deepcopy({"sgs": self.sgs, "acls": self.acls, "enis": self.enis,
                              "subnets": self.subnets, "instances": self.instances, "vpcs": self.vpcs})

    def world(self) -> dict:
        return {"sgs": self.sgs, "acls": self.acls, "enis": self.enis, "subnets": self.subnets,
                "instances": self.instances, "vpcs": self.vpcs}

    # ── plumbing ────────────────────────────────────────────────────────────────

    def call(self, op: str, write: bool, fn):
        self.chaos(op, "before", write)
        if write and self.write_denied:
            raise ClientError("UnauthorizedOperation", "You are not authorized to perform this operation.", 403, op)
        out = fn()
        if write:
            self.chaos(op, "after", write)
        return out

    def _sg(self, sg_id: str, op: str) -> dict:
        sg = self.sgs.get(sg_id)
        if sg is None:
            raise ClientError("InvalidGroup.NotFound", f"The security group '{sg_id}' does not exist", 400, op)
        return sg

    def _acl(self, acl_id: str, op: str) -> dict:
        acl = self.acls.get(acl_id)
        if acl is None:
            raise ClientError("InvalidNetworkAclID.NotFound", f"The network ACL '{acl_id}' does not exist", 400, op)
        return acl

    def _eni_view(self, e: dict, index: int = 0) -> dict:
        return {"NetworkInterfaceId": e["id"], "SubnetId": e["subnet"], "VpcId": e["vpc"],
                "Attachment": {"DeviceIndex": index, "InstanceId": e["instance"]},
                "PrivateIpAddresses": [{"PrivateIpAddress": ip, "Primary": i == 0} for i, ip in enumerate(e["ips"])],
                "Groups": [{"GroupId": g, "GroupName": self.sgs[g]["name"] if g in self.sgs else ""}
                           for g in e["groups"]]}

    def _sg_view(self, sg: dict) -> dict:
        return {"GroupId": sg["id"], "GroupName": sg["name"], "VpcId": sg["vpc"],
                "Tags": [{"Key": k, "Value": v} for k, v in sg["tags"].items()],
                "IpPermissions": [_sg_perm(r) for r in sg["ingress"]],
                "IpPermissionsEgress": [_sg_perm(r) for r in sg["egress"]]}

    def _acl_view(self, acl: dict) -> dict:
        entries = []
        for e in list(acl["entries"].values()) + [acl_entry(32767, False, "deny", "0.0.0.0/0"),
                                                  acl_entry(32767, True, "deny", "0.0.0.0/0")]:
            v = {"RuleNumber": e["number"], "Egress": e["egress"], "RuleAction": e["action"],
                 "Protocol": e["proto"], "CidrBlock": e["cidr"]}
            if e["from"] is not None:
                v["PortRange"] = {"From": e["from"], "To": e["to"]}
            entries.append(v)
        return {"NetworkAclId": acl["id"], "VpcId": acl["vpc"], "IsDefault": acl["default"], "Entries": entries,
                "Associations": [{"NetworkAclId": acl["id"], "SubnetId": s["id"]}
                                 for s in self.subnets.values() if s["acl"] == acl["id"]]}

    # ── EC2, as boto3 names it ──────────────────────────────────────────────────

    def describe_instances(self, InstanceIds):
        def read():
            out = []
            for iid in InstanceIds:
                inst = self.instances.get(iid)
                if inst is None:
                    raise ClientError("InvalidInstanceID.NotFound", f"The instance ID '{iid}' does not exist",
                                      400, "DescribeInstances")
                # A terminated instance is still described a while, without its ENIs (H16).
                first = self.enis[inst["enis"][0]] if inst["enis"] else {"vpc": "", "subnet": ""}
                out.append({"InstanceId": iid, "VpcId": first["vpc"], "SubnetId": first["subnet"],
                            **({"Platform": "windows"} if inst["platform"] == "windows" else {}),
                            "NetworkInterfaces": [self._eni_view(self.enis[e], i) for i, e in enumerate(inst["enis"])]})
            return {"Reservations": [{"Instances": out}]}
        return self.call("instance.describe", False, read)

    def describe_network_interfaces(self, NetworkInterfaceIds):
        def read():
            out = []
            for eid in NetworkInterfaceIds:
                e = self.enis.get(eid)
                if e is None:
                    raise ClientError("InvalidNetworkInterfaceID.NotFound", f"The networkInterface ID '{eid}' "
                                      "does not exist", 400, "DescribeNetworkInterfaces")
                inst = self.instances.get(e["instance"]) or {"enis": [eid]}
                out.append(self._eni_view(e, inst["enis"].index(eid)))
            return {"NetworkInterfaces": out}
        return self.call("eni.describe", False, read)

    def modify_network_interface_attribute(self, NetworkInterfaceId, Groups):
        op = "ModifyNetworkInterfaceAttribute"

        def write():
            e = self.enis.get(NetworkInterfaceId)
            if e is None:
                raise ClientError("InvalidNetworkInterfaceID.NotFound", f"'{NetworkInterfaceId}' does not exist", 400, op)
            groups = list(Groups)
            if not groups:
                raise ClientError("InvalidParameterValue", "at least one security group is required", 400, op)
            if len(groups) > _SG_MAX:
                raise ClientError("SecurityGroupsPerInterfaceLimitExceeded", "too many groups", 400, op)
            for g in groups:
                if g not in self.sgs or self.sgs[g]["vpc"] != e["vpc"]:
                    raise ClientError("InvalidGroup.NotFound", f"The security group '{g}' does not exist in "
                                      f"VPC '{e['vpc']}'", 400, op)
            if e["policy"]:
                raise ClientError("UnauthorizedOperation", f"explicit deny in a service control policy "
                                  f"({NetworkInterfaceId})", 403, op)
            before = list(e["groups"])
            e["groups"] = groups
            self.journal.append({"op": "eni.groups", "eni": e["id"], "before": before, "after": list(groups)})
            return {}
        return self.call("eni.write", True, write)

    def describe_security_groups(self, GroupIds=None, Filters=None):
        def read():
            if GroupIds:
                return {"SecurityGroups": [self._sg_view(self._sg(g, "DescribeSecurityGroups")) for g in GroupIds]}
            found = list(self.sgs.values())
            for f in Filters or []:
                key, values = f["Name"], set(f["Values"])
                field = {"vpc-id": "vpc", "group-name": "name", "group-id": "id"}[key]
                found = [s for s in found if s[field] in values]
            return {"SecurityGroups": [self._sg_view(s) for s in found]}
        return self.call("sg.describe", False, read)

    def create_security_group(self, GroupName, Description, VpcId, TagSpecifications=()):
        op = "CreateSecurityGroup"

        def write():
            if VpcId not in self.vpcs:
                raise ClientError("InvalidVpcID.NotFound", f"'{VpcId}' does not exist", 400, op)
            if any(s["vpc"] == VpcId and s["name"] == GroupName for s in self.sgs.values()):
                raise ClientError("InvalidGroup.Duplicate", f"'{GroupName}' already exists in {VpcId}", 400, op)
            self._n += 1
            sg_id = f"sg-g{self._n:04d}"
            tags = {t["Key"]: t["Value"] for spec in TagSpecifications or [] for t in spec.get("Tags", [])}
            self.add_sg(VpcId, sg_id, GroupName, egress=[sg_rule(cidr="0.0.0.0/0")], tags=tags)    # H3
            self.journal.append({"op": "sg.create", "sg": sg_id, "name": GroupName, "tags": dict(tags)})
            return {"GroupId": sg_id}
        return self.call("sg.create", True, write)

    def _sg_rules_write(self, op: str, side: str, add: bool, GroupId, IpPermissions):
        def write():
            sg = self._sg(GroupId, op)
            rules = _sg_rules(IpPermissions)
            current = sg[side]
            for r in rules:                                                     # H9: all or nothing
                if add and r in current:
                    raise ClientError("InvalidPermission.Duplicate", f"the rule already exists in {GroupId}", 400, op)
                if not add and r not in current:
                    raise ClientError("InvalidPermission.NotFound", f"the rule does not exist in {GroupId}", 400, op)
            for r in rules:
                if add:
                    current.append(r)
                else:
                    current.remove(r)
            self.journal.append({"op": "sg.rules", "sg": GroupId, "side": side, "add": add})
            return {"Return": True}
        return self.call("sg.rules", True, write)

    def authorize_security_group_ingress(self, GroupId, IpPermissions):
        return self._sg_rules_write("AuthorizeSecurityGroupIngress", "ingress", True, GroupId, IpPermissions)

    def authorize_security_group_egress(self, GroupId, IpPermissions):
        return self._sg_rules_write("AuthorizeSecurityGroupEgress", "egress", True, GroupId, IpPermissions)

    def revoke_security_group_ingress(self, GroupId, IpPermissions):
        return self._sg_rules_write("RevokeSecurityGroupIngress", "ingress", False, GroupId, IpPermissions)

    def revoke_security_group_egress(self, GroupId, IpPermissions):
        return self._sg_rules_write("RevokeSecurityGroupEgress", "egress", False, GroupId, IpPermissions)

    def _tags_of(self, rid: str, op: str) -> dict:
        if rid in self.sgs:
            return self.sgs[rid]["tags"]
        if rid in self.enis:
            return self.enis[rid].setdefault("tags", {})
        raise ClientError("InvalidID", f"'{rid}' is not a taggable resource here", 400, op)

    def create_tags(self, Resources, Tags):
        def write():
            for rid in Resources:
                tags = self._tags_of(rid, "CreateTags")
                self.journal.append({"op": "tags", "resource": rid, "before": dict(tags)})
                tags.update({t["Key"]: t["Value"] for t in Tags})                       # H7: merge
            return {}
        return self.call("tags.write", True, write)

    def delete_tags(self, Resources, Tags):
        def write():
            for rid in Resources:
                tags = self._tags_of(rid, "DeleteTags")
                self.journal.append({"op": "tags", "resource": rid, "before": dict(tags)})
                for t in Tags:
                    tags.pop(t["Key"], None)
            return {}
        return self.call("tags.write", True, write)

    def describe_network_acls(self, NetworkAclIds=None, Filters=None):
        def read():
            if NetworkAclIds:
                return {"NetworkAcls": [self._acl_view(self._acl(a, "DescribeNetworkAcls")) for a in NetworkAclIds]}
            found = list(self.acls.values())
            for f in Filters or []:
                if f["Name"] == "association.subnet-id":
                    ids = {self.subnets[s]["acl"] for s in f["Values"] if s in self.subnets}
                    found = [a for a in found if a["id"] in ids]
                elif f["Name"] == "vpc-id":
                    found = [a for a in found if a["vpc"] in f["Values"]]
            return {"NetworkAcls": [self._acl_view(a) for a in found]}
        return self.call("acl.describe", False, read)

    def create_network_acl_entry(self, NetworkAclId, RuleNumber, Protocol, RuleAction, Egress, CidrBlock,
                                 PortRange=None):
        op = "CreateNetworkAclEntry"

        def write():
            acl = self._acl(NetworkAclId, op)
            if not 1 <= int(RuleNumber) <= 32766:
                raise ClientError("InvalidParameterValue", f"rule number {RuleNumber} out of range", 400, op)
            k = (bool(Egress), int(RuleNumber))
            if k in acl["entries"]:
                raise ClientError("NetworkAclEntryAlreadyExists", f"entry {RuleNumber} already exists", 400, op)
            if sum(1 for e in acl["entries"] if e[0] == bool(Egress)) >= _ACL_MAX:
                raise ClientError("NetworkAclEntryLimitExceeded", "too many entries", 400, op)
            pr = PortRange or {}
            entry = acl_entry(int(RuleNumber), bool(Egress), str(RuleAction).lower(), CidrBlock, str(Protocol),
                              pr.get("From"), pr.get("To"))
            acl["entries"][k] = entry
            self.authored[(acl["id"], *k)] = dict(entry)
            self.journal.append({"op": "acl.create", "acl": acl["id"], "egress": k[0], "number": k[1]})
            return {}
        return self.call("acl.write", True, write)

    def delete_network_acl_entry(self, NetworkAclId, RuleNumber, Egress):
        op = "DeleteNetworkAclEntry"

        def write():
            acl = self._acl(NetworkAclId, op)
            k = (bool(Egress), int(RuleNumber))
            if k not in acl["entries"]:
                raise ClientError("InvalidNetworkAclEntry.NotFound", f"entry {RuleNumber} does not exist", 400, op)
            entry = acl["entries"].pop(k)
            mine = self.authored.get((acl["id"], *k))
            self.journal.append({"op": "acl.delete", "acl": acl["id"], "egress": k[0], "number": k[1],
                                 "authored": mine is not None and mine == entry})
            if mine == entry:
                self.authored.pop((acl["id"], *k), None)
            return {}
        return self.call("acl.write", True, write)


# ── traffic, evaluated as AWS does ───────────────────────────────────────────────

INTERNET = "203.0.113.7"          # documentation range (RFC 5737)
LATERAL = "10.9.9.9"              # in 10/8, in neither VPC
ATTACKER = "192.31.196.7"         # public for Python's ipaddress (AS112, RFC 7534): no real host
AWS_DNS = "169.254.169.253"       # Amazon's DNS resolver (also VPC base + 2)
AWS_IMDS = "169.254.169.254"
PROBES = (("in", INTERNET, 22), ("in", INTERNET, 443), ("in", LATERAL, 22),
          ("out", INTERNET, 443), ("out", LATERAL, 445),
          ("out", AWS_DNS, 53), ("out", AWS_IMDS, 80),
          ("in", ATTACKER, 22), ("in", ATTACKER, 443), ("out", ATTACKER, 443))
PLATFORM = (AWS_DNS, AWS_IMDS)
EPHEMERAL = 49152                 # the client side of an answer


def _covers(cidr: str | None, ip: str) -> bool:
    if not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _port_ok(lo, hi, port: int) -> bool:
    return lo is None or (int(lo) <= port <= int(hi if hi is not None else lo))


def _sg_allows(world: dict, groups: list[str], side: str, peer: str, port: int, proto: str) -> bool:
    """H1: any rule of any group. A rule naming a group admits that group's members only:
    no probe peer is an ENI of the world."""
    for g in groups:
        for r in world["sgs"].get(g, {}).get(side, []):
            if r["proto"] in ("-1", proto) and _port_ok(r["from"], r["to"], port) and _covers(r["cidr"], peer):
                return True
    return False


def _acl_allows(acl: dict, egress: bool, peer: str, port: int, proto: str) -> bool:
    """H5: the lowest entry that matches decides; none → the `*` entry denies."""
    number = {"tcp": "6", "udp": "17"}[proto]
    for (eg, _), e in sorted(acl["entries"].items(), key=lambda kv: kv[0][1]):
        if eg != egress or e["proto"] not in ("-1", number):
            continue
        if _covers(e["cidr"], peer) and _port_ok(e["from"], e["to"], port):
            return e["action"] == "allow"
    return False


def open_flows(world: dict, iid: str) -> frozenset:
    """The probes that get through, for every IP of every ENI of the instance."""
    out = set()
    for eni_id in world["instances"][iid]["enis"]:
        e = world["enis"][eni_id]
        acl = world["acls"][world["subnets"][e["subnet"]]["acl"]]
        for direction, peer, port in PROBES:
            proto = "udp" if port == 53 else "tcp"
            for ip in e["ips"]:
                if peer in PLATFORM:                                                   # H6
                    ok = direction == "out"
                elif direction == "in":
                    ok = (_sg_allows(world, e["groups"], "ingress", peer, port, proto)
                          and _acl_allows(acl, False, peer, port, proto) and _acl_allows(acl, True, peer, EPHEMERAL, proto))
                else:
                    ok = (_sg_allows(world, e["groups"], "egress", peer, port, proto)
                          and _acl_allows(acl, True, peer, port, proto) and _acl_allows(acl, False, peer, EPHEMERAL, proto))
                if ok:
                    out.add((eni_id, ip, direction, peer, port))
    return frozenset(out)
