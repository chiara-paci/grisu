
from .. import commands
from .. import base as base_grisu
from . import base

# OpenSSL

class OpenSSLCertificateVT(base.OnSNISocketVulnTest):
    flags=["--openssl-cert"]
    dest="openssl_cert"
    name="OpenSSLCertificate"
    command=commands.OpenSSLCertificate

base_grisu.TestRegister.register(OpenSSLCertificateVT)

class TestsslVulnerabilityVT(base.OnSNISocketVulnTest):
    flags=["--testssl-vuln"]
    dest="testssl_vuln"
    name="TestsslVulnerability"
    command=commands.TestsslVulnerability

base_grisu.TestRegister.register(TestsslVulnerabilityVT)
