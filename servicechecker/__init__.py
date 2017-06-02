#!/usr/bin/env python
# Import gevent.monkey and do the monkey patching
from gevent import monkey; monkey.patch_all()  # noqa

import json
import os

from contextlib import contextmanager
from datetime import datetime

import gevent
import statsd
import urllib3

statsd_client = None
# The following environment variables must ALL be set in order for
# statsd to work at all.
try:
    statsd_host = os.environ.get('STATSD_HOST')
    statsd_port = int(os.environ.get('STATSD_PORT'))
    statsd_prefix = os.environ.get('STATSD_PREFIX')
    statsd_client = statsd.StatsClient(statsd_host, statsd_port)
except:
    statsd_client = None


@contextmanager
def time_to_statsd(label):
    """
    Utility wrapper for statsd reporting.

    Allows to perform actions in a context, time the wall
    clock execution time, and report that value to statsd in milliseconds.
    """
    start = datetime.utcnow()
    yield
    delta = datetime.utcnow() - start
    if statsd_client is not None:
        try:
            statsd_label = "{prefix}.{label}".format(prefix=statsd_prefix, label=label)
            gevent.spawn(statsd_client.timing, statsd_label, delta.total_seconds() * 1000)
        except:
            # Statsd reporting is a secundary function of this code: if it fails, we're ok
            # with it and it should not interfere with completing the checks.
            pass


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

    def _spawn_downloader(self):
        """
        Spawns an urllib3.Poolmanager with the correct configuration.
        """
        kw = {
            # 'retries': 1, uncomment this once we've got rid of trusty
            'timeout': self._timeout
        }
        kw['ca_certs'] = "/etc/ssl/certs/ca-certificates.crt"
        kw['cert_reqs'] = 'CERT_REQUIRED'
        return urllib3.PoolManager(**kw)
