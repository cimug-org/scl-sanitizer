#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2026 Mario Dimitri Capuozzo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

IEC 61850 SCL Sanitizer
"""

import sys
import os
import re
import ipaddress
import random
import string
import hashlib
from typing import Dict, Set, Optional, Tuple
from lxml import etree as ET

# Rule 1: Namespace constant
SCL_NS = "http://www.iec.ch/61850/2003/SCL"
NSMAP = {"scl": SCL_NS}

# Rule 1: Length Constraints
MAX_IED_NAME = 32
MAX_ACCESSPOINT_NAME = 32
MAX_LDEVICE_INST = 32
MAX_CONTROL_BLOCK_NAME = 32
MAX_RPT_ID = 64
MAX_GENERIC_ID = 64 

# Rule 7.5: VLAN range (exclude 001) & 14 uniqueness handled by RNG + usage sets
VLAN_MIN = 2
VLAN_MAX = 999

# Rule 15: Basic Types allowlist
BASIC_TYPES: Set[str] = {
    "BOOLEAN","INT8","INT16","INT24","INT32","INT64","INT128",
    "UINT8","UINT16","UINT24","UINT32","UINT64",
    "FLOAT32","FLOAT64","VisString32","VisString64","VisString129","VisString255",
    "Octet64","Unicode255","ObjRef","Timestamp","Quality","Check",
    "BinaryTime","EntryTime","PhyComAddr","INT8U","INT16U","INT32U"
}

# Rule 14.1: NATO words for identifier generation
WORDS = [
    "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel","india","juliet",
    "kilo","lima","mike","november","oscar","papa","quebec","romeo","sierra","tango",
    "uniform","victor","whiskey","xray","yankee","zulu"
]

# Rule 13: Preserve only OCL ERROR comments
OCL_ERROR_COMMENT_RE = re.compile(r'^\s*OCL ERROR')

class Randomizer:
    # Rule 14.4 / 14.5 / 14.7: Seed-based deterministic mode
    def __init__(self, seed: Optional[int]):
        self.seed = seed
        self.rng = random.Random(seed) if seed is not None else random.SystemRandom()

    # Rule 14.1 / 14.2 / 14.3: Identifier generation respecting length
    def word(self, max_len: int) -> str:
        while True:
            base = self.rng.choice(WORDS)
            suffix = ''.join(self.rng.choices(string.ascii_lowercase + string.digits, k=4))
            candidate = f"{base}_{suffix}"
            if len(candidate) <= max_len:
                return candidate

    # Rule 7.4: MAC randomization (multicast prefix)
    def mac(self) -> str:
        return "01-0C-CD-" + "-".join(f"{self.rng.randint(0,255):02X}" for _ in range(3))

    # Rule 7.5: VLAN randomization
    def vlan(self) -> str:
        return f"{self.rng.randint(VLAN_MIN, VLAN_MAX):03d}"

    # Rule 7.2: Host IP randomization within allocated subnet
    def host(self, net: ipaddress.IPv4Network) -> str:
        hosts = list(net.hosts())
        return str(self.rng.choice(hosts))

class IdRegistry:
    # Rule 14.2: Uniqueness guarantee with per-category sets
    def __init__(self, rnd: Randomizer):
        self.rnd = rnd
        self.maps: Dict[str, Dict[str, str]] = {}
        self.used: Dict[str, Set[str]] = {}

    def _init_cat(self, cat: str):
        if cat not in self.maps:
            self.maps[cat] = {}
        if cat not in self.used:
            self.used[cat] = set()

    def get_or_create(self, cat: str, old: Optional[str], max_len: int) -> Optional[str]:
        if not old:
            return old
        self._init_cat(cat)
        if old in self.maps[cat]:
            return self.maps[cat][old]
        while True:
            candidate = self.rnd.word(max_len)
            if candidate not in self.used[cat]:
                self.used[cat].add(candidate)
                self.maps[cat][old] = candidate
                return candidate

    def has_old(self, cat: str, old: Optional[str]) -> bool:
        return bool(old) and old in self.maps.get(cat, {})

    def new(self, cat: str, old: Optional[str]) -> Optional[str]:
        if not old:
            return old
        return self.maps.get(cat, {}).get(old)

def parse_xml(path: str) -> ET._ElementTree:
    # Rule 17.5: Preserve comments (we selectively remove later)
    parser = ET.XMLParser(remove_blank_text=False, remove_comments=False)
    return ET.parse(path, parser)

def apply_deletions(root: ET._Element):
    # Rule 2.1: Remove Private
    for priv in root.xpath(".//scl:Private", namespaces=NSMAP):
        parent = priv.getparent()
        if parent is not None:
            parent.remove(priv)
    # Rule 2.2: Remove non-IEC namespace
    for el in list(root.iter()):
        if not isinstance(el, ET._Element):
            continue
        uri = get_namespace_uri(el.tag)
        if uri is not None and uri != SCL_NS:
            parent = el.getparent()
            if parent is not None:
                parent.remove(el)

def get_namespace_uri(tag: str) -> Optional[str]:
    if not isinstance(tag, str):
        return None
    if tag.startswith("{"):
        return tag[1:].split("}")[0]
    return None

def is_scl_element(node) -> bool:
    if not isinstance(node, ET._Element):
        return False
    uri = get_namespace_uri(node.tag)
    return (uri == SCL_NS) or (uri is None and node.tag == "SCL")

def enforce_namespace_cleanup(tree: ET._ElementTree) -> ET._Element:
    # Rule 2.3: Remove foreign namespaced attributes; keep only IEC root namespace
    original_root = tree.getroot()
    for el in original_root.iter():
        for attr in list(el.attrib):
            if attr.startswith("{"):
                uri = attr[1:].split("}")[0]
                if uri != SCL_NS:
                    del el.attrib[attr]
    if original_root.tag.startswith("{"):
        _, local = original_root.tag[1:].split("}", 1)
    else:
        local = original_root.tag
    new_root = ET.Element(f"{{{SCL_NS}}}{local}", nsmap={None: SCL_NS})
    for attr, val in original_root.attrib.items():
        if attr.startswith("{"):
            uri = attr[1:].split("}")[0]
            if uri == SCL_NS:
                new_root.set(attr, val)
        else:
            new_root.set(attr, val)
    for child in list(original_root):
        if is_scl_element(child):
            new_root.append(child)
    tree._setroot(new_root)
    return new_root

def sanitize_header(root: ET._Element, rnd: Randomizer) -> Tuple[Optional[str], Optional[str]]:
    # Rule 3.1 / 3.2 / 3.3
    # Returns (original_header_id, new_header_id) for Rule 5.4 sync
    hdr = root.find("scl:Header", namespaces=NSMAP)
    if hdr is None:
        return None, None
    
    old_id = hdr.get("id")
    new_id = rnd.word(MAX_GENERIC_ID)
    
    hdr.attrib["id"] = new_id
    for attr in ("toolID","version","revision"):
        if attr in hdr.attrib:
            hdr.attrib[attr] = rnd.word(MAX_GENERIC_ID)
            
    txt = hdr.find("scl:Text", namespaces=NSMAP)
    if txt is not None:
        txt.text = " ".join(rnd.word(16) for _ in range(3))
    for hist in hdr.findall("scl:History", namespaces=NSMAP):
        hdr.remove(hist)
        
    return old_id, new_id

def collect_ids(root: ET._Element, reg: IdRegistry):
    # Rule 5.1, 5.2, 5.3, 6.1, 8.1, 9.1, 9.2, 11.1–11.4
    # Rule 20: DataSet
    # Rule 21: Substation Topology
    
    for ied in root.xpath(".//scl:IED", namespaces=NSMAP):
        reg.get_or_create("IED.name", ied.get("name"), MAX_IED_NAME)
    for ap in root.xpath(".//scl:AccessPoint", namespaces=NSMAP):
        reg.get_or_create("AccessPoint.name", ap.get("name"), MAX_ACCESSPOINT_NAME)
    for ld in root.xpath(".//scl:LDevice", namespaces=NSMAP):
        reg.get_or_create("LDevice.inst", ld.get("inst"), MAX_LDEVICE_INST)
    
    dtt = root.find("scl:DataTypeTemplates", namespaces=NSMAP)
    if dtt is not None:
        for ln in dtt.xpath("scl:LNodeType", namespaces=NSMAP):
            reg.get_or_create("LNodeType.id", ln.get("id"), MAX_GENERIC_ID)
        for dt in dtt.xpath("scl:DOType", namespaces=NSMAP):
            reg.get_or_create("DOType.id", dt.get("id"), MAX_GENERIC_ID)
        for da in dtt.xpath("scl:DAType", namespaces=NSMAP):
            reg.get_or_create("DAType.id", da.get("id"), MAX_GENERIC_ID)
        for en in dtt.xpath("scl:EnumType", namespaces=NSMAP):
            reg.get_or_create("EnumType.id", en.get("id"), MAX_GENERIC_ID)
            
    for rpt in root.xpath(".//scl:ReportControl", namespaces=NSMAP):
        reg.get_or_create("ReportControl.rptID", rpt.get("rptID"), MAX_RPT_ID)
        reg.get_or_create("ReportControl.name", rpt.get("name"), MAX_CONTROL_BLOCK_NAME)
        
    for tag in ("GSE","SMV"):
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
            reg.get_or_create("GSESMV.cbName", el.get("cbName"), MAX_CONTROL_BLOCK_NAME)
            
    # Rule 20.1: DataSet names
    for ds in root.xpath(".//scl:DataSet", namespaces=NSMAP):
        reg.get_or_create("DataSet.name", ds.get("name"), MAX_GENERIC_ID)

    # Rule 21.1: Substation Topology
    for tag in ["Substation", "VoltageLevel", "Bay", "ConnectivityNode", "ConductingEquipment", "SubEquipment"]:
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
             reg.get_or_create(f"{tag}.name", el.get("name"), MAX_GENERIC_ID)

def apply_primary_renames(root: ET._Element, reg: IdRegistry, rnd: Randomizer, 
                         header_id_map: Tuple[Optional[str], Optional[str]]):
    # Rule 4.1, 5.*, 6.1, 11.*, 9.*, 8.*, 20.*, 21.*
    old_hdr_id, new_hdr_id = header_id_map
    
    for sn in root.xpath(".//scl:SubNetwork", namespaces=NSMAP):
        if sn.get("name"):
            sn.set("name", rnd.word(MAX_GENERIC_ID))
            
    for ied in root.xpath(".//scl:IED", namespaces=NSMAP):
        old = ied.get("name")
        if reg.has_old("IED.name", old):
            ied.set("name", reg.new("IED.name", old))
        
        # Rule 5.4: Owner/Header Sync
        owner = ied.get("owner")
        if owner and old_hdr_id and owner == old_hdr_id:
            ied.set("owner", new_hdr_id)
        elif owner:
            ied.set("owner", rnd.word(MAX_GENERIC_ID))
            
        for attr in ("type","manufacturer","configVersion"):
            if attr in ied.attrib:
                ied.set(attr, rnd.word(MAX_GENERIC_ID))
                
    for ap in root.xpath(".//scl:AccessPoint", namespaces=NSMAP):
        old = ap.get("name")
        if reg.has_old("AccessPoint.name", old):
            ap.set("name", reg.new("AccessPoint.name", old))
            
    dtt = root.find("scl:DataTypeTemplates", namespaces=NSMAP)
    if dtt is not None:
        for ln in dtt.xpath("scl:LNodeType", namespaces=NSMAP):
            oid = ln.get("id")
            if reg.has_old("LNodeType.id", oid):
                ln.set("id", reg.new("LNodeType.id", oid))
        for dt in dtt.xpath("scl:DOType", namespaces=NSMAP):
            oid = dt.get("id")
            if reg.has_old("DOType.id", oid):
                dt.set("id", reg.new("DOType.id", oid))
        for da in dtt.xpath("scl:DAType", namespaces=NSMAP):
            oid = da.get("id")
            if reg.has_old("DAType.id", oid):
                da.set("id", reg.new("DAType.id", oid))
        for en in dtt.xpath("scl:EnumType", namespaces=NSMAP):
            oid = en.get("id")
            if reg.has_old("EnumType.id", oid):
                en.set("id", reg.new("EnumType.id", oid))
                
    for rpt in root.xpath(".//scl:ReportControl", namespaces=NSMAP):
        rid = rpt.get("rptID"); nm = rpt.get("name")
        if reg.has_old("ReportControl.rptID", rid):
            rpt.set("rptID", reg.new("ReportControl.rptID", rid))
        if reg.has_old("ReportControl.name", nm):
            rpt.set("name", reg.new("ReportControl.name", nm))
            
    for tag in ("GSE","SMV"):
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
            cb = el.get("cbName")
            if reg.has_old("GSESMV.cbName", cb):
                el.set("cbName", reg.new("GSESMV.cbName", cb))

    # Rule 20.1: Rename DataSets
    for ds in root.xpath(".//scl:DataSet", namespaces=NSMAP):
        nm = ds.get("name")
        if reg.has_old("DataSet.name", nm):
            ds.set("name", reg.new("DataSet.name", nm))

    # Rule 21.1: Rename Substation Topology
    # Note: We do this top-down so we can construct the path map in synchronize_references, 
    # but the actual attribute set happens here.
    for tag in ["Substation", "VoltageLevel", "Bay", "ConnectivityNode", "ConductingEquipment", "SubEquipment"]:
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
            nm = el.get("name")
            if reg.has_old(f"{tag}.name", nm):
                el.set("name", reg.new(f"{tag}.name", nm))

def synchronize_references(root: ET._Element, reg: IdRegistry):
    # Rule 11.1–11.4, 11.5, 12.*, 8.2, 8.3, 9.3, 20.2, 21.2
    
    # 1. Standard Type References
    for ln in root.xpath(".//scl:LN | .//scl:LN0", namespaces=NSMAP):
        lt = ln.get("lnType")
        if reg.has_old("LNodeType.id", lt):
            ln.set("lnType", reg.new("LNodeType.id", lt))
    for do in root.xpath(".//scl:LNodeType/scl:DO", namespaces=NSMAP):
        t = do.get("type")
        if reg.has_old("DOType.id", t):
            do.set("type", reg.new("DOType.id", t))
    for sdo in root.xpath(".//scl:DOType/scl:SDO", namespaces=NSMAP):
        t = sdo.get("type")
        if reg.has_old("DOType.id", t):
            sdo.set("type", reg.new("DOType.id", t))
    for da in root.xpath(".//scl:DOType/scl:DA", namespaces=NSMAP):
        t = da.get("type"); bType = da.get("bType")
        if t:
            if bType == "Enum" and reg.has_old("EnumType.id", t):
                da.set("type", reg.new("EnumType.id", t))
            elif reg.has_old("DAType.id", t):
                da.set("type", reg.new("DAType.id", t))
            else:
                if t not in BASIC_TYPES and not reg.has_old("EnumType.id", t):
                    da.set("type", reg.get_or_create("UserType.literal", t, MAX_GENERIC_ID))
    for elem in root.xpath(".//scl:DAType/scl:DA | .//scl:DAType/scl:BDA", namespaces=NSMAP):
        t = elem.get("type"); bType = elem.get("bType")
        if t:
            if bType == "Enum" and reg.has_old("EnumType.id", t):
                elem.set("type", reg.new("EnumType.id", t))
            elif reg.has_old("DAType.id", t):
                elem.set("type", reg.new("DAType.id", t))
            else:
                if t not in BASIC_TYPES and not reg.has_old("EnumType.id", t):
                    elem.set("type", reg.get_or_create("UserType.literal", t, MAX_GENERIC_ID))
                    
    # 2. Communications References
    for cap in root.xpath(".//scl:ConnectedAP", namespaces=NSMAP):
        iedName = cap.get("iedName"); apName = cap.get("apName")
        if reg.has_old("IED.name", iedName):
            cap.set("iedName", reg.new("IED.name", iedName))
        if reg.has_old("AccessPoint.name", apName):
            cap.set("apName", reg.new("AccessPoint.name", apName))
    for sv in root.xpath(".//scl:ServerAt", namespaces=NSMAP):
        apName = sv.get("apName")
        if reg.has_old("AccessPoint.name", apName):
            sv.set("apName", reg.new("AccessPoint.name", apName))
    for inode in root.xpath(".//scl:IEDName", namespaces=NSMAP):
        txt = (inode.text or "").strip()
        if reg.has_old("IED.name", txt):
            inode.text = reg.new("IED.name", txt)
            
    # 3. ClientLN (Rule 3 in prompt / 12.4 in doc)
    for cln in root.xpath(".//scl:ClientLN", namespaces=NSMAP):
        iedName = cln.get("iedName")
        apRef = cln.get("apRef")
        apName = cln.get("apName") # Sometimes used
        ldInst = cln.get("ldInst")
        
        if reg.has_old("IED.name", iedName):
            cln.set("iedName", reg.new("IED.name", iedName))
            
        # Ref can be apRef or apName
        if apRef and reg.has_old("AccessPoint.name", apRef):
            cln.set("apRef", reg.new("AccessPoint.name", apRef))
        if apName and reg.has_old("AccessPoint.name", apName):
            cln.set("apName", reg.new("AccessPoint.name", apName))
            
        if reg.has_old("LDevice.inst", ldInst):
            cln.set("ldInst", reg.new("LDevice.inst", ldInst))
            
        nm = cln.get("name")
        if reg.has_old("ReportControl.name", nm):
            cln.set("name", reg.new("ReportControl.name", nm))

    # 4. LNode & FCDA
    for ln in root.xpath(".//scl:LNode", namespaces=NSMAP):
        iedName = ln.get("iedName"); ldInst = ln.get("ldInst")
        if reg.has_old("IED.name", iedName):
            ln.set("iedName", reg.new("IED.name", iedName))
        if reg.has_old("LDevice.inst", ldInst):
            ln.set("ldInst", reg.new("LDevice.inst", ldInst))
    for fcda in root.xpath(".//scl:FCDA", namespaces=NSMAP):
        ldInst = fcda.get("ldInst")
        if reg.has_old("LDevice.inst", ldInst):
            fcda.set("ldInst", reg.new("LDevice.inst", ldInst))
            
    # 5. GSE / SMV LDevice Refs
    for tag in ("GSE","SMV"):
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
            ldInst = el.get("ldInst")
            if reg.has_old("LDevice.inst", ldInst):
                el.set("ldInst", reg.new("LDevice.inst", ldInst))
                
    # 6. LDevice Inst Rename (Self)
    for ld in root.xpath(".//scl:LDevice", namespaces=NSMAP):
        inst = ld.get("inst")
        if reg.has_old("LDevice.inst", inst):
            new_inst = reg.new("LDevice.inst", inst)
            ld.set("inst", new_inst)
            if ld.get("name") == inst:
                ld.set("name", new_inst)
                
    # 7. Control Blocks & ExtRef
    for ctl_tag in ("GSEControl","SampledValueControl"):
        for ctl in root.xpath(f".//scl:{ctl_tag}", namespaces=NSMAP):
            nm = ctl.get("name")
            if reg.has_old("GSESMV.cbName", nm):
                ctl.set("name", reg.new("GSESMV.cbName", nm))
                
    for ext in root.xpath(".//scl:ExtRef", namespaces=NSMAP):
        rptID = ext.get("rptID"); rcbName = ext.get("rcbName")
        if reg.has_old("ReportControl.rptID", rptID):
            ext.set("rptID", reg.new("ReportControl.rptID", rptID))
        if reg.has_old("ReportControl.name", rcbName):
            ext.set("rcbName", reg.new("ReportControl.name", rcbName))

    # 8. DataSet References (Rule 20.2)
    # Control blocks often refer to a dataset via 'datSet' attribute
    for cb_tag in ("ReportControl", "GSEControl", "SampledValueControl", "GSE", "SMV"):
        for el in root.xpath(f".//scl:{cb_tag}", namespaces=NSMAP):
            ds = el.get("datSet")
            if reg.has_old("DataSet.name", ds):
                el.set("datSet", reg.new("DataSet.name", ds))

    # 9. Substation ConnectivityNode Path Construction (Rule 21.2)
    # We must traverse the substation tree to rebuild paths because we don't know the full old path just from registry
    # We iterate the XML which has NEW names now. We need to find the Terminal, see its OLD path, and map to NEW path.
    # Since we can't easily get the "old" path from the "new" XML structure directly without a map,
    # we will reconstruct the NEW path for every ConnectivityNode and match it against Terminals that point to the OLD node.
    # WAIT: The Terminals still have the OLD path string in them (we haven't touched them yet).
    # But the ConnectivityNodes have NEW names.
    # This implies we need a map of OldPath -> NewPath.
    
    # We can build this map by iterating the tree and looking up the REVERSE mapping in the registry?
    # No, simpler: We already have the registry which maps OldName -> NewName.
    # We can't easily reconstruct the OldPath from the tree because the tree now has NewNames.
    # Strategy: Find all Terminals. Parse their 'connectivityNode' attribute (Sub/Volt/Bay/Node).
    # Split that string. Look up each component in the registry (New -> Old? No, Old -> New).
    # The string in Terminal is "OldSub/OldVolt/OldBay/OldNode".
    # We take each part, look up reg.new(Category, part). Reassemble.
    
    for term in root.xpath(".//scl:Terminal", namespaces=NSMAP):
        cnode_path = term.get("connectivityNode")
        if not cnode_path:
            continue
            
        parts = cnode_path.split('/')
        # Structure is usually: Substation/VoltageLevel/Bay/ConnectivityNode
        # But could be Substation/VoltageLevel/ConnectivityNode (no Bay)
        # We try to map every segment.
        
        new_parts = []
        for p in parts:
            # We don't strictly know which category 'p' belongs to (Sub? Volt? Bay?).
            # However, our registry maps are disjoint enough or we can try them in order.
            # Actually, names might overlap across categories.
            # Best effort: Try specific categories based on depth? No, hierarchy varies.
            # Robust approach: check if 'p' is in *any* of the topology registries.
            
            found = None
            for cat in ["Substation.name", "VoltageLevel.name", "Bay.name", "ConnectivityNode.name"]:
                if reg.has_old(cat, p):
                    found = reg.new(cat, p)
                    break
            
            if found:
                new_parts.append(found)
            else:
                # If part not found in registry, keep it (might be a static string or skipped)
                new_parts.append(p)
                
        new_path = "/".join(new_parts)
        term.set("connectivityNode", new_path)

    # Also update the pathName attribute on the ConnectivityNode itself
    for cn in root.xpath(".//scl:ConnectivityNode", namespaces=NSMAP):
        old_path = cn.get("pathName")
        if old_path:
            parts = old_path.split('/')
            new_parts = []
            for p in parts:
                found = None
                for cat in ["Substation.name", "VoltageLevel.name", "Bay.name", "ConnectivityNode.name"]:
                    if reg.has_old(cat, p):
                        found = reg.new(cat, p)
                        break
                new_parts.append(found if found else p)
            cn.set("pathName", "/".join(new_parts))


def randomize_addresses(root: ET._Element, rnd: Randomizer):
    # Rule 7.1 / 7.2 / 7.3 / 7.4 / 7.5 / 7.6 (single pass)
    used_subnets: Set[str] = set()
    def allocate_subnet() -> ipaddress.IPv4Network:
        while True:
            x = rnd.rng.randint(1,254)
            cidr = f"10.{x}.0.0/24"
            if cidr not in used_subnets:
                used_subnets.add(cidr)
                return ipaddress.ip_network(cidr)
    cap_subnets: Dict[ET._Element, ipaddress.IPv4Network] = {}
    for cap in root.xpath(".//scl:ConnectedAP", namespaces=NSMAP):
        cap_subnets[cap] = allocate_subnet()
        for addr in cap.xpath("scl:Address", namespaces=NSMAP):
            for p in addr.xpath("scl:P", namespaces=NSMAP):
                t = p.get("type")
                if t == "IP":
                    p.text = rnd.host(cap_subnets[cap])
                elif t == "IP-SUBNET":
                    p.text = "255.255.255.0"
                elif t == "MAC-Address":
                    p.text = rnd.mac()
                elif t == "VLAN-ID":
                    p.text = rnd.vlan()
    for tag in ("GSE","SMV"):
        for el in root.xpath(f".//scl:{tag}", namespaces=NSMAP):
            ancestor_cap = el.getparent()
            while ancestor_cap is not None and ancestor_cap.tag != f"{{{SCL_NS}}}ConnectedAP":
                ancestor_cap = ancestor_cap.getparent()
            subnet = cap_subnets.get(ancestor_cap) if ancestor_cap is not None else None
            for addr in el.xpath("scl:Address", namespaces=NSMAP):
                for p in addr.xpath("scl:P", namespaces=NSMAP):
                    t = p.get("type")
                    if t == "IP" and subnet is not None:
                        p.text = rnd.host(subnet)
                    elif t == "MAC-Address":
                        p.text = rnd.mac()
                    elif t == "VLAN-ID":
                        p.text = rnd.vlan()
                    elif t == "IP-SUBNET" and subnet is not None:
                        p.text = "255.255.255.0"

def clear_desc(root: ET._Element):
    # Rule 10.1
    for e in root.xpath(".//*[@desc]", namespaces=NSMAP):
        e.set("desc","")

def handle_comments(root: ET._Element):
    # Rule 13.1–13.3
    for comment in root.xpath("//comment()"):
        txt = comment.text or ""
        if OCL_ERROR_COMMENT_RE.search(txt):
            continue
        parent = comment.getparent()
        if parent is not None:
            parent.remove(comment)

def validate(root: ET._Element):
    # Rule 16.1 / 16.5
    enum_ids = {en.get("id") for en in root.xpath(".//scl:EnumType", namespaces=NSMAP)}
    for da in root.xpath(".//scl:DOType/scl:DA | .//scl:DAType/scl:DA | .//scl:DAType/scl:BDA", namespaces=NSMAP):
        if da.get("bType") == "Enum":
            t = da.get("type")
            if t not in enum_ids:
                raise ValueError(f"Dangling EnumType reference: {t}")
    do_ids = {dt.get("id") for dt in root.xpath(".//scl:DOType", namespaces=NSMAP)}
    for sdo in root.xpath(".//scl:DOType/scl:SDO", namespaces=NSMAP):
        t = sdo.get("type")
        if t not in do_ids:
            raise ValueError(f"Dangling DOType reference (SDO): {t}")
    ap_names = {ap.get("name") for ap in root.xpath(".//scl:AccessPoint", namespaces=NSMAP)}
    for sv in root.xpath(".//scl:ServerAt", namespaces=NSMAP):
        apName = sv.get("apName")
        if apName and apName not in ap_names:
            raise ValueError(f"Dangling ServerAt.apName={apName}")

def verify_length_compliance(root: ET._Element):
    # Rule 16.6 (length compliance)
    def too_long(val: Optional[str], limit: int) -> bool:
        return val is not None and len(val) > limit
    for ied in root.xpath(".//scl:IED", namespaces=NSMAP):
        if too_long(ied.get("name"), MAX_IED_NAME):
            raise ValueError(f"IED@name exceeds length limit: {ied.get('name')}")
    for ap in root.xpath(".//scl:AccessPoint", namespaces=NSMAP):
        if too_long(ap.get("name"), MAX_ACCESSPOINT_NAME):
            raise ValueError(f"AccessPoint@name exceeds length limit: {ap.get('name')}")
    for ld in root.xpath(".//scl:LDevice", namespaces=NSMAP):
        if too_long(ld.get("inst"), MAX_LDEVICE_INST):
            raise ValueError(f"LDevice@inst exceeds length limit: {ld.get('inst')}")
    for rpt in root.xpath(".//scl:ReportControl", namespaces=NSMAP):
        if too_long(rpt.get("rptID"), MAX_RPT_ID):
            raise ValueError(f"ReportControl@rptID exceeds length limit: {rpt.get('rptID')}")
        if too_long(rpt.get("name"), MAX_CONTROL_BLOCK_NAME):
            raise ValueError(f"ReportControl@name exceeds length limit: {rpt.get('name')}")

def derive_hash_seed(path: str) -> int:
    # Rule 14.4 (hash seed derivation)
    with open(path, "rb") as f:
        data = f.read()
    sha = hashlib.sha256(data).hexdigest()
    return int(sha[:8], 16)

def force_multiline_root(root: ET._Element):
    """
    Rule 17.5 (pretty formatting) & formatting requirement:
    Ensure first child (Header) appears on its own line by injecting newline whitespace.
    """
    if not root.text or not root.text.strip():
        root.text = "\n  "
    for i, child in enumerate(root):
        if i == len(root) - 1:
            child.tail = "\n"
        else:
            child.tail = "\n  "

def serialize(root: ET._Element, seed: Optional[int], seed_source: Optional[str]) -> str:
    # Rule 17.1–17.3: Insert version & seed comments beneath XML declaration
    xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=False, pretty_print=True).decode("utf-8")
    if "<Header" in xml_body and "<SCL" in xml_body:
        xml_body = re.sub(r"(<SCL\b[^>]*>)\s*(<Header\b)", r"\1\n  \2", xml_body, count=1)
    meta_lines = ["<!-- SanitizerVersion=v2.9.0 -->"]
    if seed is not None:
        meta_lines.append(f"<!-- SanitizerSeed={seed} -->")
    if seed_source:
        meta_lines.append(f"<!-- SanitizerSeedSource={seed_source} -->")
    decl = "<?xml version='1.0' encoding='UTF-8'?>"
    return "\n".join([decl] + meta_lines + [xml_body])

def sanitize(path: str, seed: Optional[int] = None, hash_seed: bool = False, debug: bool = False) -> str:
    # Orchestrator: Implements Rules 2–21 sequence
    if seed is not None and hash_seed:
        raise ValueError("Use either --seed OR --hash-seed, not both.")
    seed_source = None
    if seed is not None:
        seed_source = "explicit"
    elif hash_seed:
        seed = derive_hash_seed(path)
        seed_source = "hash"
    rnd = Randomizer(seed)
    tree = parse_xml(path)
    root = tree.getroot()
    apply_deletions(root)
    root = enforce_namespace_cleanup(tree)
    # Header sanitation returns map of old->new ID for IED owner sync
    header_id_map = sanitize_header(root, rnd)
    reg = IdRegistry(rnd)
    collect_ids(root, reg)
    apply_primary_renames(root, reg, rnd, header_id_map)
    synchronize_references(root, reg)
    randomize_addresses(root, rnd)
    clear_desc(root)
    handle_comments(root)
    validate(root)
    verify_length_compliance(root)
    force_multiline_root(root)
    non_comment_children = [c for c in root if isinstance(c, ET._Element)]
    if len(non_comment_children) == 0:
        raise ValueError("Sanitized output empty (no IEC SCL child elements remain).")
    final_text = serialize(root, seed, seed_source)
    out = os.path.splitext(path)[0] + "_sanitized" + os.path.splitext(path)[1]
    with open(out, "w", encoding="utf-8") as f:
        f.write(final_text)
    if debug:
        print(f"[DEBUG] Wrote sanitized file: {out}", file=sys.stderr)
    return out

def main():
    # CLI harness (Rule 17.5 output, Rule 14 deterministic options)
    import argparse
    parser = argparse.ArgumentParser(description="IEC 61850 SCL Sanitizer v2.9.0 (Substation Topology & DataSet support)")
    parser.add_argument("file", help="Input SCL file")
    parser.add_argument("--seed", type=int, default=None, help="Explicit deterministic seed (Rule 14.4)")
    parser.add_argument("--hash-seed", action="store_true", help="Deterministic hash-based seed (Rule 14.4)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    try:
        out = sanitize(args.file, seed=args.seed, hash_seed=args.hash_seed, debug=args.debug)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"Sanitized file: {out}")

if __name__ == "__main__":
    main()