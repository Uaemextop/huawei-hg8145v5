"""
Tests for web_crawler.auth.aws_sig — AWS Signature V4 pre-signed URL utilities.

The reference URL from the LMSA firmware download service is::

    https://rsddownload-secure.lenovo.com/LamuC_FlashTool_Console_LMSA_5.2404.03_release.zip
    ?X-Amz-Algorithm=AWS4-HMAC-SHA256
    &X-Amz-Date=20260304T032129Z
    &X-Amz-SignedHeaders=host
    &X-Amz-Expires=604800
    &X-Amz-Credential=AKIAS37TSJMJUUCJCY4T%2F20260304%2Fus-east-1%2Fs3%2Faws4_request
    &X-Amz-Signature=80cf27ffcf2b712147f1ad5cab0a5a4f605e542a4ab5875db976cc7322f51332
"""

import hashlib
import hmac
import unittest

from web_crawler.auth.aws_sig import (
    AWS4_ALGORITHM,
    compute_presigned_signature,
    compute_signing_key,
    curl_command,
    is_presigned_s3_url,
    parse_presigned_s3_url,
    presigned_canonical_request,
    presigned_string_to_sign,
    print_analysis,
)

# ---------------------------------------------------------------------------
# Reference pre-signed URL from the problem statement (LMSA 2026-03-04)
# ---------------------------------------------------------------------------
_PRESIGNED_URL = (
    "https://rsddownload-secure.lenovo.com"
    "/LamuC_FlashTool_Console_LMSA_5.2404.03_release.zip"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    "&X-Amz-Date=20260304T032129Z"
    "&X-Amz-SignedHeaders=host"
    "&X-Amz-Expires=604800"
    "&X-Amz-Credential=AKIAS37TSJMJUUCJCY4T%2F20260304%2Fus-east-1%2Fs3%2Faws4_request"
    "&X-Amz-Signature=80cf27ffcf2b712147f1ad5cab0a5a4f605e542a4ab5875db976cc7322f51332"
)

# Unsigned URL (no X-Amz-* params) for the same host
_UNSIGNED_URL = (
    "https://rsddownload-secure.lenovo.com"
    "/fastboot_lamuc_g_user_15_VVTB35.41-41_93e397_release-keys_elabel_XT2623-2_demogb.zip"
)


class TestIsPresignedS3Url(unittest.TestCase):
    """is_presigned_s3_url() correctly identifies pre-signed URLs."""

    def test_presigned_url_detected(self):
        self.assertTrue(is_presigned_s3_url(_PRESIGNED_URL))

    def test_unsigned_url_not_detected(self):
        self.assertFalse(is_presigned_s3_url(_UNSIGNED_URL))

    def test_plain_https_url_not_detected(self):
        self.assertFalse(is_presigned_s3_url("https://example.com/file.zip"))

    def test_partial_params_not_detected(self):
        """URL with only X-Amz-Algorithm is not a complete pre-signed URL."""
        self.assertFalse(
            is_presigned_s3_url(
                "https://example.com/file.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            )
        )

    def test_all_required_params_present(self):
        """URL with all 4 required params is detected as pre-signed."""
        url = (
            "https://s3.amazonaws.com/bucket/key"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=AKID%2F20260304%2Fus-east-1%2Fs3%2Faws4_request"
            "&X-Amz-Date=20260304T000000Z"
            "&X-Amz-Signature=abc123"
        )
        self.assertTrue(is_presigned_s3_url(url))


class TestParsePresignedS3Url(unittest.TestCase):
    """parse_presigned_s3_url() correctly parses the reference URL."""

    def setUp(self):
        self.parsed = parse_presigned_s3_url(_PRESIGNED_URL)

    def test_returns_dict_for_valid_url(self):
        self.assertIsNotNone(self.parsed)
        self.assertIsInstance(self.parsed, dict)

    def test_returns_none_for_unsigned_url(self):
        self.assertIsNone(parse_presigned_s3_url(_UNSIGNED_URL))

    def test_returns_none_for_missing_params(self):
        self.assertIsNone(parse_presigned_s3_url("https://example.com/file.zip"))

    def test_algorithm(self):
        self.assertEqual(self.parsed["algorithm"], "AWS4-HMAC-SHA256")

    def test_host(self):
        self.assertEqual(self.parsed["host"], "rsddownload-secure.lenovo.com")

    def test_path(self):
        self.assertEqual(
            self.parsed["path"],
            "/LamuC_FlashTool_Console_LMSA_5.2404.03_release.zip",
        )

    def test_date(self):
        self.assertEqual(self.parsed["date"], "20260304T032129Z")

    def test_date_short(self):
        self.assertEqual(self.parsed["date_short"], "20260304")

    def test_access_key_id(self):
        self.assertEqual(self.parsed["access_key_id"], "AKIAS37TSJMJUUCJCY4T")

    def test_region(self):
        self.assertEqual(self.parsed["region"], "us-east-1")

    def test_service(self):
        self.assertEqual(self.parsed["service"], "s3")

    def test_credential_scope(self):
        self.assertEqual(
            self.parsed["credential_scope"],
            "20260304/us-east-1/s3/aws4_request",
        )

    def test_signed_headers(self):
        self.assertEqual(self.parsed["signed_headers"], "host")

    def test_expires(self):
        self.assertEqual(self.parsed["expires"], 604800)

    def test_signature(self):
        self.assertEqual(
            self.parsed["signature"],
            "80cf27ffcf2b712147f1ad5cab0a5a4f605e542a4ab5875db976cc7322f51332",
        )

    def test_security_token_none_when_absent(self):
        self.assertIsNone(self.parsed["security_token"])

    def test_invalid_credential_format_returns_none(self):
        bad_url = (
            "https://s3.amazonaws.com/bucket/key"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=BADCREDENTIAL"
            "&X-Amz-Date=20260304T000000Z"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Expires=3600"
            "&X-Amz-Signature=abc123"
        )
        self.assertIsNone(parse_presigned_s3_url(bad_url))


class TestPresignedCanonicalRequest(unittest.TestCase):
    """presigned_canonical_request() produces the correct canonical string."""

    def setUp(self):
        self.parsed = parse_presigned_s3_url(_PRESIGNED_URL)
        self.cr = presigned_canonical_request(self.parsed)

    def test_starts_with_get(self):
        self.assertTrue(self.cr.startswith("GET\n"))

    def test_contains_canonical_uri(self):
        self.assertIn(
            "/LamuC_FlashTool_Console_LMSA_5.2404.03_release.zip", self.cr
        )

    def test_contains_host_header(self):
        self.assertIn("host:rsddownload-secure.lenovo.com", self.cr)

    def test_ends_with_unsigned_payload(self):
        self.assertTrue(self.cr.endswith("UNSIGNED-PAYLOAD"))

    def test_excludes_signature_from_query_string(self):
        # The canonical query string must NOT include X-Amz-Signature
        lines = self.cr.split("\n")
        canonical_qs = lines[2]
        self.assertNotIn("X-Amz-Signature", canonical_qs)

    def test_query_string_sorted(self):
        """Canonical query string params must be in lexicographic order."""
        lines = self.cr.split("\n")
        canonical_qs = lines[2]
        pairs = [p.split("=", 1)[0] for p in canonical_qs.split("&")]
        self.assertEqual(pairs, sorted(pairs))

    def test_has_seven_sections(self):
        """Canonical request splits into 7 parts on ``\\n``.

        Per the AWS spec the canonical-headers section must end with ``\\n``,
        which produces a blank line between the headers and the
        signed-headers string when the full canonical request is split.
        """
        parts = self.cr.split("\n")
        self.assertEqual(len(parts), 7)

    def test_signed_headers_section(self):
        """Sixth section (index 5) is the signed-headers string."""
        parts = self.cr.split("\n")
        # parts[3] = canonical header line, parts[4] = blank (trailing \n),
        # parts[5] = signed headers, parts[6] = payload hash
        self.assertEqual(parts[5], "host")


class TestPresignedStringToSign(unittest.TestCase):
    """presigned_string_to_sign() produces the correct string-to-sign."""

    def setUp(self):
        self.parsed = parse_presigned_s3_url(_PRESIGNED_URL)
        self.cr = presigned_canonical_request(self.parsed)
        self.sts = presigned_string_to_sign(self.parsed, self.cr)

    def test_starts_with_algorithm(self):
        self.assertTrue(self.sts.startswith("AWS4-HMAC-SHA256\n"))

    def test_contains_date(self):
        self.assertIn("20260304T032129Z", self.sts)

    def test_contains_credential_scope(self):
        self.assertIn("20260304/us-east-1/s3/aws4_request", self.sts)

    def test_has_four_sections(self):
        """String-to-sign has exactly 4 newline-separated sections."""
        parts = self.sts.split("\n")
        self.assertEqual(len(parts), 4)

    def test_last_section_is_hex_sha256(self):
        """Last section is a 64-character lowercase hex SHA-256 hash."""
        parts = self.sts.split("\n")
        cr_hash = parts[3]
        self.assertRegex(cr_hash, r"^[0-9a-f]{64}$")

    def test_hash_matches_canonical_request(self):
        """The hash in the string-to-sign must equal SHA-256(canonical_request)."""
        expected_hash = hashlib.sha256(self.cr.encode("utf-8")).hexdigest()
        parts = self.sts.split("\n")
        self.assertEqual(parts[3], expected_hash)


class TestComputeSigningKey(unittest.TestCase):
    """compute_signing_key() derives the correct HMAC-SHA256 signing key."""

    def _expected_key(self, secret, date, region, service):
        def _h(key, data):
            return hmac.new(key, data.encode(), hashlib.sha256).digest()
        k = _h(b"AWS4" + secret.encode(), date)
        k = _h(k, region)
        k = _h(k, service)
        k = _h(k, "aws4_request")
        return k

    def test_key_derivation_matches_manual_calculation(self):
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        date = "20260304"
        region = "us-east-1"
        service = "s3"
        result = compute_signing_key(secret, date, region, service)
        expected = self._expected_key(secret, date, region, service)
        self.assertEqual(result, expected)

    def test_key_is_bytes(self):
        key = compute_signing_key("secret", "20260304", "us-east-1", "s3")
        self.assertIsInstance(key, bytes)

    def test_key_length_is_32_bytes(self):
        key = compute_signing_key("secret", "20260304", "us-east-1", "s3")
        self.assertEqual(len(key), 32)

    def test_different_keys_for_different_regions(self):
        k1 = compute_signing_key("secret", "20260304", "us-east-1", "s3")
        k2 = compute_signing_key("secret", "20260304", "eu-west-1", "s3")
        self.assertNotEqual(k1, k2)


class TestComputePresignedSignature(unittest.TestCase):
    """compute_presigned_signature() round-trips with a known secret key."""

    def test_signature_is_64_hex_chars(self):
        """Any secret key should produce a 64-char hex signature."""
        parsed = parse_presigned_s3_url(_PRESIGNED_URL)
        sig = compute_presigned_signature("some_secret", parsed)
        self.assertRegex(sig, r"^[0-9a-f]{64}$")

    def test_wrong_secret_does_not_match_reference_signature(self):
        """Using a wrong secret should not reproduce the reference signature."""
        parsed = parse_presigned_s3_url(_PRESIGNED_URL)
        sig = compute_presigned_signature("wrong_secret_key", parsed)
        self.assertNotEqual(
            sig,
            "80cf27ffcf2b712147f1ad5cab0a5a4f605e542a4ab5875db976cc7322f51332",
        )

    def test_correct_secret_reproduces_signature(self):
        """A known-correct secret must reproduce the expected signature.

        This test uses a self-consistent synthetic URL (not the captured
        Lenovo URL) so we can verify the full round-trip without knowing
        the real AWS secret key.
        """
        # Build a minimal synthetic pre-signed URL with a known secret.
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        date_short = "20260304"
        region = "us-east-1"
        service = "s3"
        cred_scope = f"{date_short}/{region}/{service}/aws4_request"
        akid = "AKIAIOSFODNN7EXAMPLE"

        parsed = {
            "algorithm":        "AWS4-HMAC-SHA256",
            "host":             "example-bucket.s3.amazonaws.com",
            "path":             "/test-object.zip",
            "date":             f"{date_short}T000000Z",
            "date_short":       date_short,
            "access_key_id":    akid,
            "region":           region,
            "service":          service,
            "credential_scope": cred_scope,
            "signed_headers":   "host",
            "expires":          3600,
            "signature":        "",  # placeholder; will be replaced
            "security_token":   None,
            "extra_params":     {},
            "_qs": {
                "X-Amz-Algorithm":  "AWS4-HMAC-SHA256",
                "X-Amz-Credential": f"{akid}/{cred_scope}",
                "X-Amz-Date":       f"{date_short}T000000Z",
                "X-Amz-Expires":    "3600",
                "X-Amz-SignedHeaders": "host",
            },
        }

        # Compute the expected signature manually using the same algorithm.
        cr  = presigned_canonical_request(parsed)
        sts = presigned_string_to_sign(parsed, cr)
        signing_key = compute_signing_key(secret, date_short, region, service)
        expected_sig = hmac.new(
            signing_key, sts.encode("utf-8"), hashlib.sha256
        ).digest().hex()

        # The function must produce the same result.
        self.assertEqual(compute_presigned_signature(secret, parsed), expected_sig)


class TestAws4AlgorithmConstant(unittest.TestCase):
    def test_algorithm_constant(self):
        self.assertEqual(AWS4_ALGORITHM, "AWS4-HMAC-SHA256")


# ---------------------------------------------------------------------------
# Second reference URL — JSON config file (same credential scope, new path)
# ---------------------------------------------------------------------------
# https://rsddownload-secure.lenovo.com/
#   Rescue_MTK_Lamu_FastbootConnect_V1_DAUpdate_DriverPrompt_20260112.json
#   ?X-Amz-Algorithm=AWS4-HMAC-SHA256
#   &X-Amz-Date=20260304T032129Z
#   &X-Amz-SignedHeaders=host
#   &X-Amz-Expires=604800
#   &X-Amz-Credential=AKIAS37TSJMJUUCJCY4T%2F20260304%2Fus-east-1%2Fs3%2Faws4_request
#   &X-Amz-Signature=08544f3db0b47996b3332387a6001d78f543218d7021b4a8f7f57b178ea398ff
_JSON_URL = (
    "https://rsddownload-secure.lenovo.com"
    "/Rescue_MTK_Lamu_FastbootConnect_V1_DAUpdate_DriverPrompt_20260112.json"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    "&X-Amz-Date=20260304T032129Z"
    "&X-Amz-SignedHeaders=host"
    "&X-Amz-Expires=604800"
    "&X-Amz-Credential=AKIAS37TSJMJUUCJCY4T%2F20260304%2Fus-east-1%2Fs3%2Faws4_request"
    "&X-Amz-Signature=08544f3db0b47996b3332387a6001d78f543218d7021b4a8f7f57b178ea398ff"
)


class TestParseJsonPresignedUrl(unittest.TestCase):
    """parse_presigned_s3_url() correctly parses the JSON config URL."""

    def setUp(self):
        self.parsed = parse_presigned_s3_url(_JSON_URL)

    def test_returns_dict_for_valid_url(self):
        self.assertIsNotNone(self.parsed)
        self.assertIsInstance(self.parsed, dict)

    def test_is_presigned_detected(self):
        self.assertTrue(is_presigned_s3_url(_JSON_URL))

    def test_algorithm(self):
        self.assertEqual(self.parsed["algorithm"], "AWS4-HMAC-SHA256")

    def test_host(self):
        self.assertEqual(self.parsed["host"], "rsddownload-secure.lenovo.com")

    def test_path(self):
        self.assertEqual(
            self.parsed["path"],
            "/Rescue_MTK_Lamu_FastbootConnect_V1_DAUpdate_DriverPrompt_20260112.json",
        )

    def test_date(self):
        self.assertEqual(self.parsed["date"], "20260304T032129Z")

    def test_date_short(self):
        self.assertEqual(self.parsed["date_short"], "20260304")

    def test_access_key_id(self):
        self.assertEqual(self.parsed["access_key_id"], "AKIAS37TSJMJUUCJCY4T")

    def test_region(self):
        self.assertEqual(self.parsed["region"], "us-east-1")

    def test_service(self):
        self.assertEqual(self.parsed["service"], "s3")

    def test_credential_scope(self):
        self.assertEqual(
            self.parsed["credential_scope"],
            "20260304/us-east-1/s3/aws4_request",
        )

    def test_expires(self):
        self.assertEqual(self.parsed["expires"], 604800)

    def test_signature(self):
        self.assertEqual(
            self.parsed["signature"],
            "08544f3db0b47996b3332387a6001d78f543218d7021b4a8f7f57b178ea398ff",
        )

    def test_security_token_none(self):
        self.assertIsNone(self.parsed["security_token"])


class TestJsonUrlCanonicalRequest(unittest.TestCase):
    """presigned_canonical_request() is correct for the JSON URL."""

    def setUp(self):
        self.parsed = parse_presigned_s3_url(_JSON_URL)
        self.cr = presigned_canonical_request(self.parsed)

    def test_starts_with_get(self):
        self.assertTrue(self.cr.startswith("GET\n"))

    def test_contains_json_path(self):
        self.assertIn(
            "/Rescue_MTK_Lamu_FastbootConnect_V1_DAUpdate_DriverPrompt_20260112.json",
            self.cr,
        )

    def test_contains_host_header(self):
        self.assertIn("host:rsddownload-secure.lenovo.com", self.cr)

    def test_ends_with_unsigned_payload(self):
        self.assertTrue(self.cr.endswith("UNSIGNED-PAYLOAD"))

    def test_excludes_signature_param(self):
        lines = self.cr.split("\n")
        self.assertNotIn("X-Amz-Signature", lines[2])

    def test_query_string_sorted(self):
        lines = self.cr.split("\n")
        keys = [p.split("=", 1)[0] for p in lines[2].split("&")]
        self.assertEqual(keys, sorted(keys))


class TestSameCredentialDifferentPath(unittest.TestCase):
    """Two URLs that share a credential scope but differ only in path must
    produce different canonical requests, different strings-to-sign, and
    therefore different signatures — even when signed with the same key.

    This is the core property that makes pre-signed URLs object-specific:
    the signature binds to the exact S3 object key (path).
    """

    def setUp(self):
        self.parsed_zip  = parse_presigned_s3_url(_PRESIGNED_URL)
        self.parsed_json = parse_presigned_s3_url(_JSON_URL)

    # ------------------------------------------------------------------
    # Shared credential components
    # ------------------------------------------------------------------

    def test_same_access_key_id(self):
        self.assertEqual(
            self.parsed_zip["access_key_id"],
            self.parsed_json["access_key_id"],
        )

    def test_same_credential_scope(self):
        self.assertEqual(
            self.parsed_zip["credential_scope"],
            self.parsed_json["credential_scope"],
        )

    def test_same_date(self):
        self.assertEqual(self.parsed_zip["date"], self.parsed_json["date"])

    def test_same_region(self):
        self.assertEqual(self.parsed_zip["region"], self.parsed_json["region"])

    def test_same_service(self):
        self.assertEqual(self.parsed_zip["service"], self.parsed_json["service"])

    def test_same_host(self):
        self.assertEqual(self.parsed_zip["host"], self.parsed_json["host"])

    def test_same_expires(self):
        self.assertEqual(self.parsed_zip["expires"], self.parsed_json["expires"])

    # ------------------------------------------------------------------
    # Path-specific differences
    # ------------------------------------------------------------------

    def test_different_paths(self):
        self.assertNotEqual(self.parsed_zip["path"], self.parsed_json["path"])

    def test_different_signatures(self):
        """Captured signatures must differ because the paths differ."""
        self.assertNotEqual(
            self.parsed_zip["signature"],
            self.parsed_json["signature"],
        )

    def test_different_canonical_requests(self):
        """Canonical requests differ because they embed the object path."""
        cr_zip  = presigned_canonical_request(self.parsed_zip)
        cr_json = presigned_canonical_request(self.parsed_json)
        self.assertNotEqual(cr_zip, cr_json)

    def test_different_strings_to_sign(self):
        """Strings-to-sign differ because they hash the canonical request."""
        cr_zip  = presigned_canonical_request(self.parsed_zip)
        cr_json = presigned_canonical_request(self.parsed_json)
        sts_zip  = presigned_string_to_sign(self.parsed_zip,  cr_zip)
        sts_json = presigned_string_to_sign(self.parsed_json, cr_json)
        self.assertNotEqual(sts_zip, sts_json)

    def test_same_signing_key_different_signatures(self):
        """With an identical signing key the two paths still yield unique sigs.

        This round-trip uses a synthetic secret key.  The same
        ``compute_signing_key()`` call (same date/region/service) produces
        one shared signing key, yet ``compute_presigned_signature()`` returns
        a different hex value for each URL because the string-to-sign differs.
        """
        secret = "synthetic_test_secret_key"
        sig_zip  = compute_presigned_signature(secret, self.parsed_zip)
        sig_json = compute_presigned_signature(secret, self.parsed_json)

        # Both must be well-formed 64-char hex strings …
        self.assertRegex(sig_zip,  r"^[0-9a-f]{64}$")
        self.assertRegex(sig_json, r"^[0-9a-f]{64}$")

        # … but they must differ because the paths differ.
        self.assertNotEqual(sig_zip, sig_json)

    def test_same_signing_key_derived_for_both(self):
        """compute_signing_key() returns the identical key for both URLs
        because the credential scope (date, region, service) is shared.
        """
        secret = "synthetic_test_secret_key"
        key_zip  = compute_signing_key(
            secret,
            self.parsed_zip["date_short"],
            self.parsed_zip["region"],
            self.parsed_zip["service"],
        )
        key_json = compute_signing_key(
            secret,
            self.parsed_json["date_short"],
            self.parsed_json["region"],
            self.parsed_json["service"],
        )
        self.assertEqual(key_zip, key_json)


# ---------------------------------------------------------------------------
# curl_command() tests
# ---------------------------------------------------------------------------

class TestCurlCommand(unittest.TestCase):
    """curl_command() produces a correct, ready-to-run curl invocation."""

    def test_presigned_url_produces_curl_command(self):
        cmd = curl_command(_PRESIGNED_URL)
        self.assertIsNotNone(cmd)
        self.assertTrue(cmd.startswith("curl -L -O"))

    def test_curl_command_contains_full_url(self):
        cmd = curl_command(_PRESIGNED_URL)
        # The pre-signed URL (with X-Amz params) must appear verbatim
        self.assertIn("X-Amz-Signature=", cmd)
        self.assertIn("rsddownload-secure.lenovo.com", cmd)

    def test_unsigned_url_also_produces_curl_command(self):
        cmd = curl_command(_UNSIGNED_URL)
        self.assertIsNotNone(cmd)
        self.assertIn(_UNSIGNED_URL, cmd)

    def test_json_url_produces_curl_command(self):
        cmd = curl_command(_JSON_URL)
        self.assertIsNotNone(cmd)
        self.assertIn(".json", cmd)

    def test_non_http_url_returns_none(self):
        self.assertIsNone(curl_command("ftp://bucket/file.zip"))

    def test_empty_url_returns_none(self):
        self.assertIsNone(curl_command(""))

    def test_url_is_double_quoted(self):
        cmd = curl_command(_PRESIGNED_URL)
        # URL must be wrapped in double-quotes so shell special chars are safe
        self.assertRegex(cmd, r'curl -L -O ".*"')


# ---------------------------------------------------------------------------
# print_analysis() tests
# ---------------------------------------------------------------------------

class TestPrintAnalysis(unittest.TestCase):
    """print_analysis() produces correct human-readable output."""

    def _capture(self, url: str, secret: str = "") -> str:
        import io
        buf = io.StringIO()
        print_analysis(url, secret_key=secret, file=buf)
        return buf.getvalue()

    def test_output_contains_parsed_components_section(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("PARSED COMPONENTS", out)

    def test_output_contains_host(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("rsddownload-secure.lenovo.com", out)

    def test_output_contains_access_key(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("AKIAS37TSJMJUUCJCY4T", out)

    def test_output_contains_canonical_request_section(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("CANONICAL REQUEST", out)

    def test_output_contains_string_to_sign_section(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("STRING-TO-SIGN", out)

    def test_output_contains_signing_key_section(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("SIGNING KEY DERIVATION", out)

    def test_output_contains_curl_command(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("curl -L -O", out)

    def test_output_contains_curl_command_for_json_url(self):
        out = self._capture(_JSON_URL)
        self.assertIn("curl -L -O", out)
        self.assertIn(".json", out)

    def test_no_computed_sig_section_without_secret(self):
        out = self._capture(_PRESIGNED_URL)
        self.assertNotIn("COMPUTED SIGNATURE", out)

    def test_computed_sig_section_with_secret(self):
        out = self._capture(_PRESIGNED_URL, secret="any_key")
        self.assertIn("COMPUTED SIGNATURE", out)
        self.assertIn("Computed :", out)
        self.assertIn("Captured :", out)
        self.assertIn("Match    :", out)

    def test_wrong_secret_shows_no_match(self):
        out = self._capture(_PRESIGNED_URL, secret="wrong_key")
        self.assertIn("NO", out)

    def test_unsigned_url_shows_not_presigned_message(self):
        out = self._capture(_UNSIGNED_URL)
        self.assertIn("Not a valid pre-signed S3 URL", out)

    def test_unsigned_url_still_shows_curl(self):
        out = self._capture(_UNSIGNED_URL)
        self.assertIn("curl -L -O", out)

    def test_expires_human_readable(self):
        """604800 s = 168h 0m should appear in the output."""
        out = self._capture(_PRESIGNED_URL)
        self.assertIn("168h", out)


if __name__ == "__main__":
    unittest.main()
