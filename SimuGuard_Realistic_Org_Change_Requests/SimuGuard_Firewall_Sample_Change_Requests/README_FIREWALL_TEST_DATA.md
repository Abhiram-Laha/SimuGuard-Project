# Apex Global Technologies - Firewall Test Change Requests

These synthetic firewall change requests are grounded in the uploaded network configuration datasets:

- `firewalls.json`
- `panorama.json`
- `zones.json`
- `subnets.json`
- `interfaces.json`
- `routes.json`
- `service_objects.json`
- `address_objects.json`
- `security_policies.json`
- `nat_policies.json`

## Test scenarios

1. `01_FW_Scoped_Analytics_Webhook_Egress.txt` - narrow App-ID on an existing partner egress rule.
2. `02_FW_Wildcard_Internet_Egress_Risk.txt` - broad wildcard Internet destination.
3. `03_FW_Block_Direct_DMZ_To_CUI_Vault.txt` - direct DMZ access to restricted CUI/financial vault.
4. `04_FW_Dev_To_Production_Database_Access.txt` - development-to-production PostgreSQL access.
5. `05_FW_Public_SSH_Inbound_Exposure.txt` - public inbound SSH to a DMZ subnet.
6. `06_FW_Customer_Portal_NAT_And_Security_Rule_Change.txt` - validation of an existing static DNAT and matching security rule.
7. `07_FW_Remove_Shadowed_Duplicate_Policy.txt` - disable a duplicate/shadowed policy while retaining the primary rule.

## Data-grounding notes

- All named firewall IDs, models, Panorama device groups, zones, CIDRs, interfaces, address objects, services, policy IDs and NAT IDs are taken from the supplied JSON files.
- The supplied IP ranges are synthetic documentation ranges and internal lab ranges. These requests are for local simulation only.
- The test files describe proposed changes; they do not prove that a change is deployed or currently effective.
- Scenario 6 is a validation request. The expected system behavior is to compare the requested configuration with the baseline and avoid inventing a modification if no change is required.
- Scenario 7 requests a candidate disablement of RULE-PAN-010; the primary RULE-PAN-003 and NAT-001-DMZ-STATIC-PORTAL should remain unchanged.

## Testing guidance for SimuGuard AI

For each file, test:
1. Change ID and domain classification.
2. Target firewall and Panorama device group resolution.
3. Source/destination zone and address-object resolution.
4. CIDR and service/protocol/port resolution.
5. Application/App-ID extraction.
6. Security profile and session logging extraction.
7. Existing policy/NAT rule matching.
8. Rule order, enabled state and HA peer context where relevant.
9. Digital Twin mapping and blast-radius analysis.
10. Risk findings, score, verdict and recommendations.
11. Candidate overlay and before/after validation, where applicable.

Do not infer a firewall association solely from a zone or subnet name. Use the supplied firewall, interface, Panorama and policy relationships. If the data does not uniquely establish a target, mark it unknown or ambiguous and request review.

Do not claim that a candidate overlay changes live Panorama or production firewall configuration.
