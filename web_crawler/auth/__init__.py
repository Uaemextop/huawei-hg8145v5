"""Authentication helpers for protected download endpoints."""

from web_crawler.auth.lmsa import LMSASession
from web_crawler.auth.lenovo_id import LenovoIDAuth
from web_crawler.auth.aws_sig import (
    AWS4_ALGORITHM,
    is_presigned_s3_url,
    parse_presigned_s3_url,
    presigned_canonical_request,
    presigned_string_to_sign,
    compute_signing_key,
    compute_presigned_signature,
    curl_command,
    print_analysis,
)

__all__ = [
    "LMSASession",
    "LenovoIDAuth",
    "AWS4_ALGORITHM",
    "is_presigned_s3_url",
    "parse_presigned_s3_url",
    "presigned_canonical_request",
    "presigned_string_to_sign",
    "compute_signing_key",
    "compute_presigned_signature",
    "curl_command",
    "print_analysis",
]
