#!/usr/bin/env python
# Import gevent.monkey and do the monkey patching
from gevent import monkey; monkey.patch_all()  # noqa

import json
import urllib3


class CheckError(Exception):
    """
    Generic Exception used as a catchall
    """
    pass


def fetch_url(client, url, **kw):
    """
    Standalone function to fetch an url.

    Args:
        client (urllib3.Poolmanager):
                                 The HTTP client we want to use
        url (str): The URL to fetch

        kw: any keyword arguments we want to pass to
            urllib3.request.RequestMethods.request
    """
    if 'method' in kw:
        method = kw['method'].upper()
        del kw['method']
    else:
        method = 'GET'
    if 'headers' not in kw:
        kw['headers'] = {}
    if 'User-Agent' not in kw['headers']:
        kw['headers']['User-Agent'] = 'ServiceChecker-WMF/0.1.2'

    try:
        if method == 'GET':
            return client.request(
                method,
                url,
                **kw
            )
        elif method == 'POST':
            try:
                headers = kw.get('headers', {})
                content_type = headers.get('Content-Type', '')
            except:
                content_type = ''

            # Handle json-encoded requests
            if content_type.lower() == 'application/json':
                kw['body'] = json.dumps(kw['fields'])
                del kw['fields']
                return client.urlopen(
                    method,
                    url,
                    **kw
                )
            # Handle raw binary requests
            if content_type.lower() == 'application/octet-stream':
                body = kw['fields']
                del kw['fields']
                if isinstance(body, dict) or isinstance(body, list):
                    # assume JSON encoding for structures
                    kw['body'] = json.dumps(body)
                else:
                    kw['body'] = body
                return client.urlopen(
                    method,
                    url,
                    **kw
                )

            return client.request_encode_body(
                method,
                url,
                encode_multipart=False,
                **kw
            )
    except urllib3.exceptions.SSLError:
        raise CheckError("Invalid certificate")
    except (urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.TimeoutError,
            # urllib3.exceptions.ConnectionError, # commented out until we can
            # remove trusty (aka urllib3 1.7.1) support
            urllib3.exceptions.ReadTimeoutError):
        raise CheckError("Timeout on connection while "
                         "downloading {}".format(url))
    except Exception as e:
        raise CheckError("Generic connection error: {}".format(e))


class CheckerBase(object):
    """
    Base class to implement higher-level checkers
    """
    nagios_codes = ['OK', 'WARNING', 'CRITICAL']
    nrpe_timeout = 10

    def _spawn_downloader(self, https=False):
        """
        Spawns an urllib3.Poolmanager with the correct configuration.
        """
        kw = {
            # 'retries': 1, uncomment this once we've got rid of trusty
            'timeout': self._timeout
        }
        kw['ca_certs'] = "/etc/ssl/certs/ca-certificates.crt"
        kw['cert_reqs'] = 'CERT_REQUIRED'
        # necessary if we want to specify an IP to connect to *and*
        # an hostname we want to verify  the TLS cert against.
        if https:
            try:
                kw['assert_hostname'] = self.http_host
            except:
                pass
        return urllib3.PoolManager(**kw)
