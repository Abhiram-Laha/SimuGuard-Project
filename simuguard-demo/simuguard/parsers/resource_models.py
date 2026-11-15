"""Normalized domain models for parsed Terraform / HCL resources."""

from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class HclSyntaxError(BaseModel):
    """Represents a low-level HCL syntax parsing failure."""

    model_config = ConfigDict(extra="ignore")

    filename: str = Field(..., description="Source file where the HCL syntax error occurred")
    error_message: str = Field(..., description="Parser error message / reason")
    line_number: Optional[int] = Field(default=None, description="Line number where syntax failed")


class ProviderSchemaError(BaseModel):
    """Represents a Terraform provider schema validation error.

    Occurs when HCL syntax is valid, but the target provider resource
    contains unsupported attributes, invalid types, or missing required fields.
    """

    model_config = ConfigDict(extra="ignore")

    filename: str = Field(..., description="Source file containing the invalid resource")
    resource_type: str = Field(..., description="Terraform resource type (e.g. aws_security_group_rule)")
    resource_name: str = Field(..., description="Terraform resource label/name")
    error_message: str = Field(..., description="Explanation of the provider schema violation")
    unsupported_attributes: List[str] = Field(
        default_factory=list,
        description="Attributes present in HCL but not supported by the provider schema",
    )


class BaseTerraformResource(BaseModel):
    """Base class for all normalized Terraform resources."""

    model_config = ConfigDict(extra="ignore")

    resource_type: str = Field(..., description="Terraform resource type (e.g. panos_security_policy)")
    resource_name: str = Field(..., description="Terraform resource identifier name")
    source_file: str = Field(..., description="Filename where this resource is defined")
    raw_attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw normalized attributes dictionary extracted from HCL",
    )
    schema_errors: List[str] = Field(
        default_factory=list,
        description="Provider schema issues detected for this resource",
    )


class PanosSecurityPolicyRule(BaseModel):
    """A discrete rule block within a panos_security_policy resource."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Rule name")
    source_zones: List[str] = Field(default_factory=list, description="Source security zones")
    source_addresses: List[str] = Field(default_factory=list, description="Source IP / CIDR addresses")
    source_users: List[str] = Field(default_factory=lambda: ["any"], description="Source users or user groups")
    destination_zones: List[str] = Field(default_factory=list, description="Destination security zones")
    destination_addresses: List[str] = Field(default_factory=list, description="Destination IP / CIDR addresses")
    applications: List[str] = Field(default_factory=list, description="PAN-OS App-ID applications (e.g. ssl, web-browsing, any)")
    services: List[str] = Field(default_factory=list, description="Services / ports (e.g. service-https, application-default)")
    action: str = Field(default="allow", description="Action to take: allow, deny, drop, reset-client, reset-server, reset-both")
    security_profile_group: Optional[str] = Field(
        default=None,
        description="Attached Security Profile Group name (e.g. Strict-Enterprise-Security, none)",
    )
    description: Optional[str] = Field(default=None, description="Optional rule description")


class PanosSecurityPolicyResource(BaseTerraformResource):
    """Normalized panos_security_policy resource."""

    resource_type: Literal["panos_security_policy"] = "panos_security_policy"
    rules: List[PanosSecurityPolicyRule] = Field(
        default_factory=list,
        description="Nested rule blocks defined within this security policy",
    )


class AwsSecurityGroupRuleResource(BaseTerraformResource):
    """Normalized aws_security_group_rule resource."""

    resource_type: Literal["aws_security_group_rule"] = "aws_security_group_rule"
    rule_type: Optional[str] = Field(default=None, description="Rule direction: 'ingress' or 'egress'")
    from_port: Optional[int] = Field(default=None, description="Start of port range")
    to_port: Optional[int] = Field(default=None, description="End of port range")
    protocol: Optional[str] = Field(default=None, description="Protocol (e.g. 'tcp', 'udp', '-1')")
    cidr_blocks: List[str] = Field(default_factory=list, description="IPv4 CIDR blocks")
    ipv6_cidr_blocks: List[str] = Field(default_factory=list, description="IPv6 CIDR blocks")
    prefix_list_ids: List[str] = Field(default_factory=list, description="VPC prefix list IDs")
    security_group_id: Optional[str] = Field(default=None, description="Target Security Group ID")
    source_security_group_id: Optional[str] = Field(default=None, description="Referenced source/destination Security Group ID")
    self_reference: Optional[bool] = Field(default=None, description="Whether rule references its own security group")
    description: Optional[str] = Field(default=None, description="Rule description")
    unsupported_attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Attributes present in HCL not supported by aws_security_group_rule schema (e.g. destination)",
    )


class AwsIamRolePolicyAttachmentResource(BaseTerraformResource):
    """Normalized aws_iam_role_policy_attachment resource."""

    resource_type: Literal["aws_iam_role_policy_attachment"] = "aws_iam_role_policy_attachment"
    role: str = Field(..., description="Target IAM role name")
    policy_arn: str = Field(..., description="ARN of the attached IAM policy")


class AwsIamPolicyDocumentResource(BaseTerraformResource):
    """Normalized data.aws_iam_policy_document or aws_iam_policy_document resource."""

    resource_type: Literal["aws_iam_policy_document"] = "aws_iam_policy_document"
    statement: List[Dict[str, Any]] = Field(default_factory=list, description="IAM policy statements")


class GenericTerraformResource(BaseTerraformResource):
    """Fallback representation for other/unrecognized Terraform resources."""

    pass


NormalizedResource = Union[
    PanosSecurityPolicyResource,
    AwsSecurityGroupRuleResource,
    AwsIamRolePolicyAttachmentResource,
    AwsIamPolicyDocumentResource,
    GenericTerraformResource,
]


class ParsedTerraformFile(BaseModel):
    """Structured representation of a parsed Terraform file."""

    model_config = ConfigDict(extra="ignore")

    file_path: str = Field(..., description="Full path to the source file")
    filename: str = Field(..., description="Base filename (e.g. pr_4083_firewall_iam.tf)")
    is_valid_hcl: bool = Field(default=True, description="True if HCL syntax parsing succeeded")
    hcl_syntax_errors: List[HclSyntaxError] = Field(
        default_factory=list,
        description="Low-level HCL syntax errors",
    )
    provider_schema_errors: List[ProviderSchemaError] = Field(
        default_factory=list,
        description="Terraform provider schema mismatches / unsupported attributes",
    )
    resources: List[NormalizedResource] = Field(
        default_factory=list,
        description="List of normalized Terraform resources extracted from file",
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw parsed HCL dictionary (comments and internal markers stripped)",
    )

    @property
    def has_errors(self) -> bool:
        """Check if any HCL syntax or provider schema errors were found."""
        return bool(self.hcl_syntax_errors or self.provider_schema_errors)

    @property
    def has_syntax_errors(self) -> bool:
        """Check if any HCL syntax errors were found."""
        return bool(self.hcl_syntax_errors)

    @property
    def has_provider_errors(self) -> bool:
        """Check if any provider schema errors were found."""
        return bool(self.provider_schema_errors)


class ParseDirectoryResult(BaseModel):
    """Structured result of parsing an entire directory of Terraform files."""

    model_config = ConfigDict(extra="ignore")

    directory_path: str = Field(..., description="Path to directory parsed")
    files: List[ParsedTerraformFile] = Field(default_factory=list, description="List of parsed files")

    @property
    def total_resources(self) -> int:
        """Total number of normalized resources extracted across all files."""
        return sum(len(f.resources) for f in self.files)

    @property
    def total_hcl_syntax_errors(self) -> int:
        """Total number of HCL syntax errors across all files."""
        return sum(len(f.hcl_syntax_errors) for f in self.files)

    @property
    def total_provider_schema_errors(self) -> int:
        """Total number of provider schema errors across all files."""
        return sum(len(f.provider_schema_errors) for f in self.files)

    @property
    def all_resources(self) -> List[NormalizedResource]:
        """Flattened list of all resources across all parsed files."""
        res: List[NormalizedResource] = []
        for f in self.files:
            res.extend(f.resources)
        return res
