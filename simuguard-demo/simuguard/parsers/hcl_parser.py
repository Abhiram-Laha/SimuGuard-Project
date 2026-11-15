"""HCL and Terraform parser for SimuGuard AI.

Uses python-hcl2 to parse Terraform configurations, normalize PAN-OS and AWS resources,
and perform provider-schema validation distinguishing syntax errors from schema violations.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import hcl2
from simuguard.parsers.resource_models import (
    AwsIamPolicyDocumentResource,
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    GenericTerraformResource,
    HclSyntaxError,
    NormalizedResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
    ParseDirectoryResult,
    ParsedTerraformFile,
    ProviderSchemaError,
)

# Known valid attributes for aws_security_group_rule in Terraform AWS Provider
AWS_SG_RULE_VALID_ATTRS: Set[str] = {
    "type",
    "from_port",
    "to_port",
    "protocol",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "prefix_list_ids",
    "security_group_id",
    "source_security_group_id",
    "self",
    "description",
}


def _clean_scalar(val: Any) -> Any:
    """Strip extraneous quotes and whitespace added by python-hcl2."""
    if isinstance(val, str):
        s = val.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            if len(s) >= 2:
                s = s[1:-1]
        return s
    return val


def _normalize_data(val: Any) -> Any:
    """Recursively clean strings, strip internal metadata keys (__comments__, __is_block__)."""
    if isinstance(val, str):
        return _clean_scalar(val)
    elif isinstance(val, list):
        return [_normalize_data(item) for item in val]
    elif isinstance(val, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in val.items():
            if k.startswith("__"):
                continue
            clean_key = _clean_scalar(k)
            cleaned[clean_key] = _normalize_data(v)
        return cleaned
    return val


def _ensure_list(val: Any) -> List[Any]:
    """Ensure a value is returned as a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


class TerraformHclParser:
    """Ingestion and normalization engine for Terraform files."""

    def parse_string(self, content: str, filename: str = "inline.tf", file_path: str = "") -> ParsedTerraformFile:
        """Parse raw HCL string into structured, normalized resources.

        Distinguishes low-level HCL syntax errors from Terraform provider schema mismatches.
        """
        resolved_path = file_path or filename
        parsed_file = ParsedTerraformFile(
            file_path=resolved_path,
            filename=filename,
            is_valid_hcl=True,
        )

        try:
            raw_hcl = hcl2.loads(content)
        except Exception as exc:
            line_no = getattr(exc, "line", None)
            parsed_file.is_valid_hcl = False
            parsed_file.hcl_syntax_errors.append(
                HclSyntaxError(
                    filename=filename,
                    error_message=str(exc),
                    line_number=line_no,
                )
            )
            return parsed_file

        cleaned_data = _normalize_data(raw_hcl)
        parsed_file.raw_data = cleaned_data

        # Extract 'resource' blocks
        resource_blocks = cleaned_data.get("resource", [])
        if isinstance(resource_blocks, list):
            for res_entry in resource_blocks:
                if isinstance(res_entry, dict):
                    for res_type, instances in res_entry.items():
                        if isinstance(instances, dict):
                            for res_name, attrs in instances.items():
                                if isinstance(attrs, dict):
                                    resource = self._normalize_resource(
                                        res_type=res_type,
                                        res_name=res_name,
                                        attrs=attrs,
                                        filename=filename,
                                        parsed_file=parsed_file,
                                    )
                                    parsed_file.resources.append(resource)

        # Extract 'data' blocks (e.g. data "aws_iam_policy_document")
        data_blocks = cleaned_data.get("data", [])
        if isinstance(data_blocks, list):
            for data_entry in data_blocks:
                if isinstance(data_entry, dict):
                    for data_type, instances in data_entry.items():
                        if isinstance(instances, dict):
                            for data_name, attrs in instances.items():
                                if isinstance(attrs, dict):
                                    resource = self._normalize_data_resource(
                                        data_type=data_type,
                                        data_name=data_name,
                                        attrs=attrs,
                                        filename=filename,
                                    )
                                    parsed_file.resources.append(resource)

        return parsed_file

    def parse_file(self, file_path: Union[str, Path]) -> ParsedTerraformFile:
        """Parse a single Terraform (.tf) file from disk."""
        path = Path(file_path).resolve()
        if not path.is_file():
            return ParsedTerraformFile(
                file_path=str(path),
                filename=path.name,
                is_valid_hcl=False,
                hcl_syntax_errors=[
                    HclSyntaxError(
                        filename=path.name,
                        error_message=f"File not found or not accessible: {path}",
                    )
                ],
            )

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            return ParsedTerraformFile(
                file_path=str(path),
                filename=path.name,
                is_valid_hcl=False,
                hcl_syntax_errors=[
                    HclSyntaxError(
                        filename=path.name,
                        error_message=f"Failed to read file: {exc}",
                    )
                ],
            )

        return self.parse_string(content=content, filename=path.name, file_path=str(path))

    def parse_directory(self, dir_path: Union[str, Path], pattern: str = "*.tf") -> ParseDirectoryResult:
        """Parse all matching Terraform files in a directory."""
        directory = Path(dir_path).resolve()
        result = ParseDirectoryResult(directory_path=str(directory))

        if not directory.is_dir():
            return result

        for tf_file in sorted(directory.glob(pattern)):
            if tf_file.is_file():
                parsed = self.parse_file(tf_file)
                result.files.append(parsed)

        return result

    def _normalize_resource(
        self,
        res_type: str,
        res_name: str,
        attrs: Dict[str, Any],
        filename: str,
        parsed_file: ParsedTerraformFile,
    ) -> NormalizedResource:
        """Normalize a Terraform resource into its typed schema and validate provider rules."""
        if res_type == "panos_security_policy":
            return self._normalize_panos_security_policy(res_name, attrs, filename)

        elif res_type == "aws_security_group_rule":
            return self._normalize_aws_security_group_rule(res_name, attrs, filename, parsed_file)

        elif res_type == "aws_iam_role_policy_attachment":
            return self._normalize_aws_iam_role_policy_attachment(res_name, attrs, filename, parsed_file)

        elif res_type == "aws_iam_policy_document":
            return AwsIamPolicyDocumentResource(
                resource_type="aws_iam_policy_document",
                resource_name=res_name,
                source_file=filename,
                raw_attributes=attrs,
                statement=_ensure_list(attrs.get("statement", [])),
            )

        # Fallback for unrecognized resources
        return GenericTerraformResource(
            resource_type=res_type,
            resource_name=res_name,
            source_file=filename,
            raw_attributes=attrs,
        )

    def _normalize_panos_security_policy(
        self, res_name: str, attrs: Dict[str, Any], filename: str
    ) -> PanosSecurityPolicyResource:
        """Normalize panos_security_policy and extract its nested rule blocks."""
        raw_rules = attrs.get("rule", [])
        rules_list: List[PanosSecurityPolicyRule] = []

        for r in _ensure_list(raw_rules):
            if isinstance(r, dict):
                rule_name = r.get("name", "unnamed-rule")
                rules_list.append(
                    PanosSecurityPolicyRule(
                        name=rule_name,
                        source_zones=_ensure_list(r.get("source_zones", [])),
                        source_addresses=_ensure_list(r.get("source_addresses", [])),
                        source_users=_ensure_list(r.get("source_users", ["any"])),
                        destination_zones=_ensure_list(r.get("destination_zones", [])),
                        destination_addresses=_ensure_list(r.get("destination_addresses", [])),
                        applications=_ensure_list(r.get("applications", [])),
                        services=_ensure_list(r.get("services", [])),
                        action=r.get("action", "allow"),
                        security_profile_group=r.get("security_profile_group"),
                        description=r.get("description"),
                    )
                )

        return PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name=res_name,
            source_file=filename,
            raw_attributes=attrs,
            rules=rules_list,
        )

    def _normalize_aws_security_group_rule(
        self,
        res_name: str,
        attrs: Dict[str, Any],
        filename: str,
        parsed_file: ParsedTerraformFile,
    ) -> AwsSecurityGroupRuleResource:
        """Normalize aws_security_group_rule and identify provider schema mismatches (e.g. destination)."""
        unsupported: Dict[str, Any] = {}
        schema_errs: List[str] = []

        # Validate against known AWS Security Group Rule provider attributes
        for key, val in attrs.items():
            if key not in AWS_SG_RULE_VALID_ATTRS:
                unsupported[key] = val
                err_msg = (
                    f"Attribute '{key}' is not supported by Terraform AWS provider for resource "
                    f"'aws_security_group_rule.{res_name}'. AWS Security Groups operate at Layer 4 "
                    f"and do not accept domain names or FQDN destinations. Valid attributes are: "
                    f"{', '.join(sorted(AWS_SG_RULE_VALID_ATTRS))}."
                )
                schema_errs.append(err_msg)
                parsed_file.provider_schema_errors.append(
                    ProviderSchemaError(
                        filename=filename,
                        resource_type="aws_security_group_rule",
                        resource_name=res_name,
                        error_message=err_msg,
                        unsupported_attributes=[key],
                    )
                )

        from_port = attrs.get("from_port")
        to_port = attrs.get("to_port")

        return AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name=res_name,
            source_file=filename,
            raw_attributes=attrs,
            rule_type=attrs.get("type"),
            from_port=int(from_port) if from_port is not None and str(from_port).isdigit() else None,
            to_port=int(to_port) if to_port is not None and str(to_port).isdigit() else None,
            protocol=attrs.get("protocol"),
            cidr_blocks=_ensure_list(attrs.get("cidr_blocks", [])),
            ipv6_cidr_blocks=_ensure_list(attrs.get("ipv6_cidr_blocks", [])),
            prefix_list_ids=_ensure_list(attrs.get("prefix_list_ids", [])),
            security_group_id=attrs.get("security_group_id"),
            source_security_group_id=attrs.get("source_security_group_id"),
            self_reference=attrs.get("self"),
            description=attrs.get("description"),
            unsupported_attributes=unsupported,
            schema_errors=schema_errs,
        )

    def _normalize_aws_iam_role_policy_attachment(
        self,
        res_name: str,
        attrs: Dict[str, Any],
        filename: str,
        parsed_file: ParsedTerraformFile,
    ) -> AwsIamRolePolicyAttachmentResource:
        """Normalize aws_iam_role_policy_attachment resource."""
        role = attrs.get("role", "")
        policy_arn = attrs.get("policy_arn", "")
        schema_errs: List[str] = []

        if not role or not policy_arn:
            err = f"aws_iam_role_policy_attachment.{res_name} requires both 'role' and 'policy_arn'."
            schema_errs.append(err)
            parsed_file.provider_schema_errors.append(
                ProviderSchemaError(
                    filename=filename,
                    resource_type="aws_iam_role_policy_attachment",
                    resource_name=res_name,
                    error_message=err,
                )
            )

        return AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name=res_name,
            source_file=filename,
            raw_attributes=attrs,
            role=role,
            policy_arn=policy_arn,
            schema_errors=schema_errs,
        )

    def _normalize_data_resource(
        self,
        data_type: str,
        data_name: str,
        attrs: Dict[str, Any],
        filename: str,
    ) -> NormalizedResource:
        """Normalize data source blocks."""
        if data_type == "aws_iam_policy_document":
            return AwsIamPolicyDocumentResource(
                resource_type="aws_iam_policy_document",
                resource_name=data_name,
                source_file=filename,
                raw_attributes=attrs,
                statement=_ensure_list(attrs.get("statement", [])),
            )
        return GenericTerraformResource(
            resource_type=f"data.{data_type}",
            resource_name=data_name,
            source_file=filename,
            raw_attributes=attrs,
        )
