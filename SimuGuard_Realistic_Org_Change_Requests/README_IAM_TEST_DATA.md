# SimuGuard AI - Organization-Aligned IAM Test Requests

These synthetic test requests are based on the uploaded Apex Global Technologies IAM Digital Twin data:
- identities.json
- roles.json
- policies.json
- trust_relationships.json
- resource_policies.json

## Important source-data boundary
The supplied `identities.json` contains AWS IAM roles, IAM users, groups and service identities. It does not contain a SailPoint employee directory or named human employee records. Therefore these tests target the exact AWS IAM identities and ARNs present in the supplied dataset; they do not invent employee IDs or claim to validate human Joiner/Mover/Leaver records.

## Test files
1. `01_IAM_Analytics_Role_Overprivilege.txt` - attach AmazonS3FullAccess to the analytics ingestion role.
2. `02_IAM_Dev_To_Production_Trust_Change.txt` - cross-account trust from development to production CI/CD role without specified MFA/external ID restrictions.
3. `03_IAM_Customer_Portal_Admin_Policy_Request.txt` - request AdministratorAccess for a critical customer portal role.
4. `04_IAM_PCI_Boundary_Removal_Request.txt` - remove the PCI permission boundary from the payment processor role.
5. `05_IAM_SecOps_Cross_Account_MFA_Review.txt` - validate the existing MFA-protected SecOps audit trust path.

## Testing guidance
- Resolve each role using its exact role ARN and identity record ID.
- Compare current attachments, trust relationships and permission boundaries with the source JSON.
- Treat missing expiry, approval or trust conditions as missing information, not as safe defaults.
- Distinguish requested state from current state.
- Do not infer effective permissions from attached policies alone; account for permission boundaries and resource policies where the assessment engine supports them.
- These are simulation test inputs only. They do not authorize or perform AWS changes.
