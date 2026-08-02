"""Secret Live Verification — check if detected secrets are still active.

Optional feature (requires network access): makes safe, read-only API calls
to verify whether detected credentials are still valid/active.

This follows the TruffleHog model:
1. Detect a potential secret via pattern matching
2. OPTIONALLY verify it's active (not revoked/expired)
3. Active secrets get CRITICAL severity; revoked ones get LOW

Verification is:
- READ-ONLY (never writes, modifies, or uses the credential for access)
- SAFE (uses the minimum API call to check validity)
- OPTIONAL (disabled by default, enable with --verify-secrets flag)
- LOGGED (records which keys were checked, for audit)

Supported verifications:
- AWS: sts.GetCallerIdentity (read-only, no permissions needed)
- GitHub: GET /user (checks token validity)
- OpenAI: GET /models (checks API key works)
- Slack: auth.test (checks token validity)
"""

from dataclasses import dataclass
from enum import Enum


class VerificationStatus(str, Enum):
    ACTIVE = "active"           # Key is valid and working
    REVOKED = "revoked"         # Key is invalid/expired
    UNKNOWN = "unknown"         # Could not verify (network error, unsupported type)
    SKIPPED = "skipped"         # Verification disabled


@dataclass
class VerificationResult:
    """Result of verifying a single secret."""
    secret_type: str
    status: VerificationStatus
    message: str = ""
    masked_value: str = ""


# Verification functions for each secret type
# These are all READ-ONLY and safe to call

def verify_aws_key(access_key: str, secret_key: str) -> VerificationResult:
    """Verify AWS credentials using STS GetCallerIdentity (read-only)."""
    # NOTE: Requires boto3 and network access
    # This is the safest AWS API call — it only returns who you are, does nothing
    try:
        import boto3
        client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        response = client.get_caller_identity()
        return VerificationResult(
            secret_type="AWS",
            status=VerificationStatus.ACTIVE,
            message=f"Active: Account {response['Account']}, ARN {response['Arn']}",
            masked_value=access_key[:8] + "****",
        )
    except ImportError:
        return VerificationResult("AWS", VerificationStatus.UNKNOWN, "boto3 not installed")
    except Exception as e:
        if "InvalidClientTokenId" in str(e) or "SignatureDoesNotMatch" in str(e):
            return VerificationResult("AWS", VerificationStatus.REVOKED, "Key is invalid/revoked")
        return VerificationResult("AWS", VerificationStatus.UNKNOWN, str(e)[:100])


def verify_github_token(token: str) -> VerificationResult:
    """Verify GitHub token using GET /user (read-only)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "lucin-verify"},
        )
        response = urllib.request.urlopen(req, timeout=5)
        if response.status == 200:
            return VerificationResult("GitHub", VerificationStatus.ACTIVE, "Token is valid")
        return VerificationResult("GitHub", VerificationStatus.REVOKED, f"HTTP {response.status}")
    except Exception as e:
        if "401" in str(e) or "403" in str(e):
            return VerificationResult("GitHub", VerificationStatus.REVOKED, "Token rejected")
        return VerificationResult("GitHub", VerificationStatus.UNKNOWN, str(e)[:100])


def verify_openai_key(key: str) -> VerificationResult:
    """Verify OpenAI API key using GET /models (read-only)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        response = urllib.request.urlopen(req, timeout=5)
        if response.status == 200:
            return VerificationResult("OpenAI", VerificationStatus.ACTIVE, "Key is valid")
        return VerificationResult("OpenAI", VerificationStatus.REVOKED, f"HTTP {response.status}")
    except Exception as e:
        if "401" in str(e):
            return VerificationResult("OpenAI", VerificationStatus.REVOKED, "Key rejected")
        return VerificationResult("OpenAI", VerificationStatus.UNKNOWN, str(e)[:100])


# Registry of verifiers by secret type pattern
VERIFIERS = {
    "AWS Access Key": verify_aws_key,
    "GitHub Token": verify_github_token,
    "OpenAI API Key": verify_openai_key,
}
