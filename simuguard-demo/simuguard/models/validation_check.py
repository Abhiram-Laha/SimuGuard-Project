"""Validation check model for pre-implementation verification playbooks."""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ValidationCheck(BaseModel):
    """Represents a specific pre-implementation check to run before committing changes."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    step_number: int = Field(
        ...,
        ge=1,
        description="Step sequence number in the validation playbook (starts at 1)",
    )
    target_component: str = Field(
        ...,
        min_length=2,
        description="Infrastructure component being tested (e.g., PAN-OS Security Policy, IAM Role)",
    )
    what_to_validate: str = Field(
        ...,
        min_length=5,
        description="Human-readable explanation of what the engineer must verify",
    )
    cli_command: str = Field(
        ...,
        min_length=3,
        description="Exact PAN-OS CLI or cloud CLI command to execute before rollout",
    )
    expected_pass_criteria: str = Field(
        ...,
        min_length=3,
        description="Exact output or pattern that confirms the check has passed",
    )
    command_type: Optional[str] = Field(
        default="PAN_OS_CLI",
        description="Command platform type (e.g., PAN_OS_CLI, AWS_CLI, KUBECTL)",
    )

    @field_validator("target_component", "what_to_validate", "cli_command", "expected_pass_criteria")
    @classmethod
    def strip_and_validate_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace only")
        return cleaned
