\---

name: blast-radius-analyzer

description: Simulates Palo Alto Networks (PAN-OS) firewall rules, cloud IAM permissions, and policy updates before implementation to predict downstream blast radius, detect compliance gaps, and prescribe validation steps.

\---



\# Palo Alto \& Cloud Pre-Flight Simulation Skill



When an engineer proposes a Palo Alto firewall rule or IAM policy change:

1\. \*\*Analyze the PAN-OS Policy:\*\* Verify source/destination zones, App-ID settings (flag `any` as high risk), and ensure Security Profile Groups (Anti-Spyware/Vulnerability Protection) are enforced.

2\. \*\*Overlay Against the Digital Twin:\*\* Query `topology\_graph.json` to model how zone interconnects and IAM roles interact across the environment.

3\. \*\*Generate Palo Alto CLI Validation Checks:\*\* Formulate exact `test security-policy-match` commands that engineers must run on PAN-OS before pushing changes to production.

4\. \*\*Prescribe Remediated Config:\*\* Output a least-privilege configuration enforcing App-ID and scoped destination IPs.



