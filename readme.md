<!-- 
MIT License

Copyright (c) 2026 Mario Dimitri Capuozzo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
-->

# IEC 61850 SCL Sanitization Rules

## 0. Scope, Goals, Definitions
- Goal: Produce an anonymized SCL (Edition 2.1) that passes IEC 61850-6 XSD validation, reveals no sensitive topology or vendor data, and preserves structural integrity.
- Do NOT modify: lnClass, lnInst, prefix.
- Sensitive identifiers are randomized; vendor/private extensions deleted.
- “Randomize” = replace original with generated identifier (NATO word + underscore + 4 alphanumerics) respecting maximum length & uniqueness within category.
- Basic IEC types (Rule 15) must remain unchanged.
- Deterministic mode optional (Rule 14).

## 1. Identifier Length Constraints
Enforce maximum lengths:  
- MAX_IED_NAME (32)
- MAX_ACCESSPOINT_NAME (32)
- MAX_LDEVICE_INST (32)
- MAX_CONTROL_BLOCK_NAME (32)
- MAX_RPT_ID (64)
- MAX_GENERIC_ID (64)
- MAX_DATASET_NAME (32)
Regenerate (preferred) or truncate (fallback) to meet limits (implementation regenerates until compliant).

## 2. Deletion Rules
2.1 Delete every `<Private>` element.  
2.2 Delete any element whose namespace URI != `http://www.iec.ch/61850/2003/SCL`.  
2.3 Strip foreign namespaced attributes (`xmlns:*` except the SCL default). Retain only IEC SCL namespace on root.

## 3. Header Sanitization
3.1 Randomize `<Header>` attributes: `id`, `toolID`, `version`, `revision`.  
3.2 Randomize `<Header>/<Text>` content (if present).  
3.3 Remove all `<History>` children.
3.4 If `IED@owner` equals the original `Header@id`, the new `IED@owner` MUST equal the new `Header@id` (preservation of ownership semantics).

## 4. SubNetwork Identification
4.1 Randomize `SubNetwork@name` values.

## 5. IED-Level Anonymization
5.1 Randomize `IED@name` (respect length).  
5.2 Randomize `IED@type`, `IED@owner` (subject to Rule 3.4).  
5.3 Randomize vendor metadata: `manufacturer`, `configVersion`.  

## 6. Access Points & Server Structures
6.1 Randomize `AccessPoint@name`.  
6.2 Synchronize all references: `apName` / `apRef` / `ServerAt@apName`.  
6.3 Maintain consistent mapping across all uses of each original name.

## 7. Communication Endpoints (ConnectedAP & Addresses)
7.1 Allocate a unique non-overlapping `/24` subnet per `ConnectedAP` (format: `10.X.0.0/24`).  
7.2 Randomize host `IP` (one per P[@type="IP"] in respective subnet).  
7.3 Set `IP-SUBNET` to `255.255.255.0`.  
7.4 Randomize `MAC-Address` with multicast prefix `01-0C-CD-XX-XX-XX`.  
7.5 Randomize `VLAN-ID` within `002–999` range (inclusive).  
7.6 Single pass: do not overwrite randomized values in subsequent steps.

## 8. Control Blocks & DataSets
8.1 Randomize `ldInst` and `cbName` in `<GSE>` and `<SMV>`.  
8.2 Propagate new `ldInst` to `LDevice@inst`, `FCDA@ldInst`, and `GSE/SMV@ldInst`.  
8.3 Propagate `cbName` to associated `GSEControl@name` / `SampledValueControl@name`.
8.4 Randomize `DataSet@name`.
8.5 Propagate new `DataSet` name to `datSet` attribute in `GSEControl`, `SampledValueControl`, and `ReportControl`.

## 9. ReportControl Blocks
9.1 Randomize `ReportControl@rptID`.  
9.2 Randomize `ReportControl@name`.  
9.3 Update dependent references: `ExtRef@rptID`, `ExtRef@rcbName`, `ClientLN@name` referencing the block.

## 10. Description Attributes
10.1 Clear (`""`) all `desc` attribute values.

## 11. DataTypeTemplates – IDs & Types
11.1 Randomize `LNodeType@id` and update all `lnType` attributes.  
11.2 Randomize `DOType@id` and update `DO@type` & `SDO@type`.  
11.3 Randomize `DAType@id` and update `DA@type` references (non-basic).  
11.4 Randomize `EnumType@id` and update DA/BDA where `bType="Enum"`.  
11.5 Randomize remaining user-defined `@type` literals (DA / BDA) not in basic allowlist, ensuring consistent mapping.  
11.6 Maintain uniqueness across all randomized IDs (LNodeType, DOType, DAType, EnumType, user literals).

## 12. Reference Synchronization
12.1 `ConnectedAP@iedName` → new `IED@name`.  
12.2 `ServerAt@apName` → new `AccessPoint@name`.  
12.3 `<IEDName>` text nodes → new `IED@name`.  
12.4 `ClientLN`: update `iedName`, `apRef`/`apName`, `ldInst`, and `name` if referencing a ReportControl.  
12.5 `LNode`: update `iedName`, `ldInst`.  
12.6 `FCDA@ldInst` → new `LDevice@inst`.  
12.7 `ExtRef@rptID` and `ExtRef@rcbName` → new report identifiers.  
12.8 `GSE` / `SMV` `cbName` → `GSEControl` / `SampledValueControl@name`.  
12.9 `*Control@datSet` → new `DataSet@name`.
12.10 `Terminal@connectivityNode` (and `ConnectivityNode@pathName`) → Reconstructed path string (see Rule 20).

## 13. Comment Preservation
13.1 Preserve comments whose trimmed text starts with `OCL ERROR`.  
13.2 Remove all other comments.  
13.3 Do not alter preserved comment content.

## 14. Identifier Generation & Determinism
14.1 Pattern: NATO word + underscore + 4 lowercase alphanumerics.  
14.2 Enforce uniqueness per category via tracking sets.  
14.3 Enforce max length constraints.  
14.4 Deterministic modes:
     - `--seed <int>` explicit seed.
     - `--hash-seed` derives 32-bit seed from first 8 hex chars of SHA256(file bytes).  
14.5 Insert meta comments when deterministic:
```
<!-- SanitizerVersion=v2.9.0 -->
<!-- SanitizerSeed=<value> -->
<!-- SanitizerSeedSource=<explicit|hash> -->
```
14.6 Omit seed comments in non-deterministic mode.  
14.7 Hash seed ensures identical sanitized output for byte-identical inputs; any byte change alters seed.  

## 15. Basic Type Protection
15.1 Never randomize IEC built-in primitive types (allowlist).  
15.2 Randomize only user-defined / enumerated types & template IDs.

## 16. Validation & Integrity
16.1 All randomized references must resolve (IDs, names, `ldInst`, `rptID`, `cbName`, `type`).  
16.2 XSD validation SHOULD pass (external schema not embedded).  
16.3 Uniqueness enforced for all categories.  
16.4 Subnets must not overlap (distinct `/24`).  
16.5 No dangling `SDO@type` or enum references.  
16.6 Length compliance confirmed for identifiers post-randomization.

## 17. Output & Traceability
17.1 Include seed comments only in deterministic mode.  
17.2 Include `SanitizerSeedSource` (`explicit` | `hash`) when deterministic.  
17.3 Always include version comment `<!-- SanitizerVersion=v2.9.0 -->`.  
17.4 Preserve whitelisted OCL ERROR comments.  
17.5 Maintain XML declaration; ensure `<Header>` is on its own line (formatting aid).  
17.6 Place version/seed comments immediately after XML declaration (spec compliant).

## 18. Versioning
18.1 Increment rules version on structural or semantic changes.  

## 19. Change Log (since v2.8.1)
- Added Rule 3.4: IED Owner synchronization with Header ID.
- Added Rule 8.4/8.5/12.9: DataSet name randomization and reference updates.
- Added Rule 20/12.10: Substation topology randomization and connectivity path reconstruction.
- Version bump to 2.9.0.

## 20. Substation Topology
20.1 Randomize the `@name` attribute of ANY element within the `<Substation>` hierarchy (e.g., `Substation`, `VoltageLevel`, `Bay`, `ConductingEquipment`, `ConnectivityNode`, `Terminal`, `SubEquipment`).
20.2 All topology names share a single randomization namespace (`Topology.name`) to facilitate path reconstruction.
20.3 Reconstruct `Terminal@connectivityNode` attributes.
    - Split original path string by `/`.
    - Map each segment to its new randomized name.
    - Rejoin segments to form the new path.
    - Updates MUST respect the hierarchy: `SubstationName/VoltageLevelName/BayName/ConnectivityNodeName`.
20.4 Reconstruct `ConnectivityNode@pathName` using the same logic.

## Security / Privacy Note
- Deterministic hash seeding can correlate identical originals across organizations.
- Use non-deterministic mode when unlinkability is a priority.

## Outcome
Produces a structurally intact, anonymized SCL file safe for cross-organizational sharing. v2.9.0 adds deep topology anonymization and DataSet protection.