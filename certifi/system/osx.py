import os
import re
import subprocess


SYSTEM_KEYCHAIN = '/Library/Keychains/System.keychain'
SYSTEM_CA_KEYCHAIN = '/System/Library/Keychains/SystemRootCertificates.keychain'
USER_CA_BUNDLE = os.path.expanduser('~/Library/Caches/certifi/OS-bundle.pem')

_CERT_RE = re.compile(r'(?s)-{5}BEGIN CERTIFICATE-{5}(.*?)-{5}END CERTIFICATE-{5}')


def mtime_or_never(filename):
    try:
        mtime = os.stat(filename).st_mtime
        return mtime
    except OSError:
        return float('-inf')


def try_security():
    try:
        potential_certs = subprocess.check_output(['security', 'find-certificate', '-a', '-p'])
        valid_certs = []
        for cert in _CERT_RE.finditer(potential_certs):
            cert = '-----BEGIN CERTIFICATE-----' + cert[0] + '-----END CERTIFICATE-----'
            proc = subprocess.Popen(['openssl', 'x509', '-inform', 'pem',
                                     '-checkend', '0', '-noout'], stdin=subprocess.PIPE)
            proc.communicate(input=cert)
            proc.wait()
            if proc.returncode == 0:
                valid_certs.append(cert)
    except subprocess.CalledProcessError:
        # Assume that nothing is wrong and set this to blank
        return ''


if not os.path.exists(USER_CA_BUNDLE):
    OS_TRUSTED_CERTS = try_security()
else:
    max_time = max(mtime_or_never(SYSTEM_KEYCHAIN), mtime_or_never(SYSTEM_CA_KEYCHAIN))
    if max_time > mtime_or_never(USER_CA_BUNDLE):
        OS_TRUSTED_CERTS = try_security()
    else:
        OS_TRUSTED_CERTS = ''
