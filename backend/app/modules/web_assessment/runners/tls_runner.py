import datetime
import shutil
import socket
import ssl
import subprocess
from typing import Dict, Any, List, Optional
from app.core.config import settings


class TlsRunner:
    """
    TLS and SSL certificate inspector using Python's ssl module.
    Optionally delegates to testssl.sh if installed and configured.
    """

    def __init__(self, testssl_path: Optional[str] = None):
        self.testssl_path = testssl_path or settings.TESTSSL_PATH

    def check_tls(self, host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Inspect TLS cipher, protocols, and certificate validity on target host and port.
        """
        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "https_available": False,
            "accepted_protocols": [],
            "is_expired": False,
            "not_after": None,
            "not_before": None,
            "is_self_signed": False,
            "hostname_mismatch": False,
            "subject": None,
            "issuer": None,
            "common_name": None,
            "san": [],
            "raw_output": "",
        }

        # Step 1: Probe HTTPS reachability and verified certificate
        verified_context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with verified_context.wrap_socket(sock, server_hostname=host) as ssock:
                    result["https_available"] = True
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()
                    if proto:
                        result["accepted_protocols"].append(proto)

                    if cert:
                        self._extract_cert_details(cert, host, result)
                    result["raw_output"] = f"TLS Connection successful\nProtocol: {proto}\nCipher: {cipher}\nCert: {cert}"
                    return result

        except ssl.SSLCertVerificationError as cert_err:
            result["https_available"] = True
            result["raw_output"] += f"Certificate verification error: {cert_err.verify_message} (code: {cert_err.verify_code})\n"
            err_msg = str(cert_err).lower()
            if "expired" in err_msg or "has expired" in cert_err.verify_message.lower():
                result["is_expired"] = True
            if "self-signed" in err_msg or "self signed" in err_msg or "unable to get local issuer" in err_msg:
                result["is_self_signed"] = True
            if "hostname" in err_msg or "doesn't match" in err_msg:
                result["hostname_mismatch"] = True

        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as conn_err:
            result["raw_output"] = f"Could not establish TLS connection to {host}:{port}: {conn_err}"
            return result
        except Exception as e:
            result["raw_output"] += f"TLS probe exception: {e}\n"

        # Step 2: If verification failed, connect unverified to read certificate fields
        unverified_context = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=host) as ssock:
                    result["https_available"] = True
                    proto = ssock.version()
                    if proto and proto not in result["accepted_protocols"]:
                        result["accepted_protocols"].append(proto)
                    cert = ssock.getpeercert()
                    if cert:
                        self._extract_cert_details(cert, host, result)
        except Exception:
            pass

        # Step 3: Check for testssl.sh integration (skipped gracefully if absent)
        testssl_bin = shutil.which(self.testssl_path)
        if testssl_bin:
            try:
                proc = subprocess.run(
                    [testssl_bin, "--fast", "--quiet", "--color", "0", f"{host}:{port}"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                )
                result["raw_output"] += f"\n[testssl.sh output]\n{proc.stdout}"
            except Exception as testssl_err:
                result["raw_output"] += f"\n[testssl.sh error: {testssl_err}]\n"

        return result

    def _extract_cert_details(self, cert: Dict[str, Any], host: str, result: Dict[str, Any]) -> None:
        """Helper to extract expiry, SANs, and Common Name from ssl peer cert dict."""
        not_after_str = cert.get("notAfter")
        if not_after_str:
            result["not_after"] = not_after_str
            try:
                exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                if exp_date < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
                    result["is_expired"] = True
            except Exception:
                pass

        result["not_before"] = cert.get("notBefore")

        # Extract Subject and Issuer
        subject_tuples = cert.get("subject", ())
        issuer_tuples = cert.get("issuer", ())
        result["subject"] = str(subject_tuples)
        result["issuer"] = str(issuer_tuples)

        if subject_tuples == issuer_tuples and subject_tuples:
            result["is_self_signed"] = True

        for rdn in subject_tuples:
            for k, v in rdn:
                if k == "commonName":
                    result["common_name"] = v

        # Extract Subject Alternative Names
        san_list = []
        for typ, name in cert.get("subjectAltName", ()):
            if typ.lower() == "dns":
                san_list.append(name)
        result["san"] = san_list

        # Hostname matching check if not already flagged
        if san_list:
            if not any(self._match_hostname(host, san) for san in san_list):
                result["hostname_mismatch"] = True
        elif result.get("common_name"):
            if not self._match_hostname(host, result["common_name"]):
                result["hostname_mismatch"] = True

    @staticmethod
    def _match_hostname(hostname: str, pattern: str) -> bool:
        """Evaluate hostname against certificate CN/SAN pattern including wildcards."""
        h = hostname.lower().strip()
        p = pattern.lower().strip()
        if h == p:
            return True
        if p.startswith("*."):
            suffix = p[2:]
            return h.endswith("." + suffix) or h == suffix
        return False
