"""HTTP security headers audit."""

SECURITY_HEADERS = {
    "Strict-Transport-Security": "warn",
    "Content-Security-Policy": "warn",
    "X-Frame-Options": "warn",
    "X-Content-Type-Options": "warn",
    "Referrer-Policy": "info",
    "Permissions-Policy": "info",
}


def audit_headers(headers, report):
    """Check a response's headers for standard web security controls."""
    if headers is None:
        report.add_finding("error", "headers", "No response headers available")
        return

    for name, severity in SECURITY_HEADERS.items():
        value = headers.get(name)
        if value:
            report.add_finding(
                "info", "headers", f"{name}: present ({value[:80]})"
            )
        else:
            report.add_finding(
                severity, "headers", f"Missing security header: {name}"
            )

    hsts = headers.get("Strict-Transport-Security")
    if hsts and "includeSubDomains" not in hsts:
        report.add_finding(
            "warn", "headers",
            "Strict-Transport-Security does not include includeSubDomains",
        )
