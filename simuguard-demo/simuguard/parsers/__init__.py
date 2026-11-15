"""Parsers package for SimuGuard AI.

Responsible for ingesting and tokenizing Terraform / HCL files, extracting
Palo Alto PAN-OS (`panos_*`), AWS Security Group (`aws_security_group_rule`),
and AWS IAM (`aws_iam_*`) resources into normalized data models.
"""

from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import (
    AwsIamPolicyDocumentResource,
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    BaseTerraformResource,
    GenericTerraformResource,
    HclSyntaxError,
    NormalizedResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
    ParseDirectoryResult,
    ParsedTerraformFile,
    ProviderSchemaError,
)

__all__ = [
    "TerraformHclParser",
    "ParsedTerraformFile",
    "ParseDirectoryResult",
    "NormalizedResource",
    "BaseTerraformResource",
    "PanosSecurityPolicyResource",
    "PanosSecurityPolicyRule",
    "AwsSecurityGroupRuleResource",
    "AwsIamRolePolicyAttachmentResource",
    "AwsIamPolicyDocumentResource",
    "GenericTerraformResource",
    "HclSyntaxError",
    "ProviderSchemaError",
]
