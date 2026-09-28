"""
tools/native_probes.py — Pure-Python, read-only probes that need no
external binaries. These are safe-by-construction: each one opens a
single connection, reads a banner or does one documented protocol
handshake (e.g. anonymous FTP login, TLS handshake), and closes. No
brute forcing, no writes, no credential guessing.
"""

import socket
import ssl
import ftplib
from datetime import datetime

from .base import ToolAdapter, ToolRunResult, Finding


class BannerGrabAdapter(ToolAdapter):
    """Generic TCP banner grab — works for SSH, SMTP, FTP control banners, etc."""

    name = "banner-grab"
    requires_binary = None
    TARGET_PORTS = {21, 22, 25, 110, 143, 3306, 5432, 6379, 27017, 9200}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 5) -> ToolRunResult:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(256).decode(errors="replace").strip()
                except socket.timeout:
                    banner = ""
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        findings = []
        if banner:
            findings.append(
                Finding(
                    tool=self.name, host=host, port=port, category="banner",
                    summary=f"Service banner: {banner[:180]}", severity="info", raw=banner,
                )
            )
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings, raw_output=banner)


class TLSInspectAdapter(ToolAdapter):
    """Pulls the TLS certificate (subject, issuer, expiry, SANs) via a real handshake."""

    name = "tls-inspect"
    requires_binary = None
    TARGET_PORTS = {443, 8443, 465, 993, 995}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 6) -> ToolRunResult:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # inspecting, not trusting
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        findings = []
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            expired = False
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expired = expiry < datetime.utcnow()
            except Exception:
                pass

            findings.append(
                Finding(
                    tool=self.name, host=host, port=port, category="tls",
                    summary=f"Cert CN={subject.get('commonName','?')} issuer={issuer.get('commonName','?')} "
                            f"expires={not_after}{' (EXPIRED)' if expired else ''}, cipher={cipher[0] if cipher else '?'}",
                    severity="high" if expired else "info",
                    raw=str(cert),
                )
            )
            if expired:
                findings.append(
                    Finding(tool=self.name, host=host, port=port, category="vuln-hint",
                            summary="TLS certificate is expired.", severity="high")
                )
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings)


class AnonymousFTPAdapter(ToolAdapter):
    """
    Checks ONLY whether anonymous/anonymous login is accepted (a standard,
    widely-recognized misconfiguration check). Does not enumerate files,
    upload, download, or attempt any other credentials.
    """

    name = "ftp-anon-check"
    requires_binary = None

    def applies_to(self, port: int, service: str) -> bool:
        return port == 21

    def run(self, host: str, port: int, service: str, timeout: int = 6) -> ToolRunResult:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login("anonymous", "sentryscan@example.com")
            ftp.quit()
            anon_ok = True
        except Exception:
            anon_ok = False

        findings = []
        if anon_ok:
            findings.append(
                Finding(
                    tool=self.name, host=host, port=port, category="vuln-hint",
                    summary="Anonymous FTP login is ENABLED — server accepted anonymous credentials.",
                    severity="high",
                )
            )
        else:
            findings.append(
                Finding(tool=self.name, host=host, port=port, category="banner",
                        summary="Anonymous FTP login rejected (expected/secure).", severity="info")
            )
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings)


class HTTPHeaderAdapter(ToolAdapter):
    """Fetches root path headers only — no crawling, no path brute-forcing."""

    name = "http-headers"
    requires_binary = None
    TARGET_PORTS = {80, 8080, 8000, 8888}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 6) -> ToolRunResult:
        import urllib.request
        url = f"http://{host}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SentryScan/0.1 (authorized-recon)"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = dict(resp.getheaders())
                status = resp.status
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        server = headers.get("Server", "unknown")
        powered_by = headers.get("X-Powered-By", "")
        findings = [
            Finding(
                tool=self.name, host=host, port=port, category="web-tech",
                summary=f"HTTP {status} — Server: {server}" + (f", X-Powered-By: {powered_by}" if powered_by else ""),
                severity="info", raw=str(headers),
            )
        ]
        missing_sec_headers = [h for h in ("Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security")
                                if h not in headers]
        if missing_sec_headers:
            findings.append(
                Finding(tool=self.name, host=host, port=port, category="vuln-hint",
                        summary=f"Missing security headers: {', '.join(missing_sec_headers)}", severity="medium")
            )
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings)


NATIVE_ADAPTERS = [BannerGrabAdapter(), TLSInspectAdapter(), AnonymousFTPAdapter(), HTTPHeaderAdapter()]
