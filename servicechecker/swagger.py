#!/usr/bin/env python
# Import gevent.monkey and do the monkey patching
from gevent import monkey; monkey.patch_all()  # noqa

import argparse
from collections import namedtuple
import json
import yaml
import re
import sys
import os

import gevent

# python 2 vs python 3 imports
try:
    import urlparse
    from urllib import quote_plus
except ImportError:
    import urllib.parse as urlparse
    from urllib.parse import quote_plus

try:
    reload(sys)  # noqa
    sys.setdefaultencoding('utf-8')
except:
    pass

from servicechecker import CheckerBase, fetch_url, CheckError, logging
from servicechecker.metrics import Null as NullMetrics
from servicechecker.metrics import StatsD as StatsDMetrics


class CheckService(CheckerBase):
    """
    Shell class for checking services
    """
    default_request = {
        'request': {},
        'response': {'status': 200},
        'title': 'Untitled test'
    }
    _supported_methods = ['get', 'post']

    def __init__(self, host_ip, base_url, timeout=5, spec_url='/?spec',
                 metrics_manager=None, insecure=False):
        """
        Initialize the checker

        Args:
            host_ip (str): The host ipv4 address (also works with a hostname)

            base_url (str): The base url the service expects to respond from

            timeout (int): Number of seconds to wait for each request

            spec_url (str): the string to append to the base url, defaults to
                           /?spec
           metrics_manager (Metrics): Instance of Metrics implementation or None. default: None
        """
        self.host_ip = host_ip
        self.base_url = urlparse.urlsplit(base_url)
        http_host_port = self.base_url.netloc.split(':')
        if len(http_host_port) < 2:
            if self.base_url.scheme == 'https':
                http_host_port.append('443')
            else:
                http_host_port.append('80')
        self.http_host, self.port = http_host_port
        self._url_prefix = self.base_url.path
        self.endpoints = {}
        self._timeout = timeout
        self.spec_url = spec_url
        self.is_https = (self.base_url.scheme == 'https')
        self.insecure = insecure
        if metrics_manager is None:
            self.metrics_manager = NullMetrics()
        else:
            self.metrics_manager = metrics_manager

    @property
    def _url(self):
        """
        Returns an url pointing to the IP of the host to check.
        """
        return "{}://{}:{}".format(self.base_url.scheme,
                                   self.host_ip,
                                   self.port)

    def get_endpoints(self):
        """
        Gets the full spec from base_url + '/?spec' and parses it.
        Returns a generator iterating over the available endpoints
        """
        http = self._spawn_downloader(self.is_https, self.insecure)
        # TODO: cache all this.
        response = fetch_url(
            http,
            self._url + self._url_prefix + self.spec_url,
            timeout=self._timeout,
            headers={'Host': self.http_host}
        )

        resp = response.data.decode('utf-8')

        try:
            r = json.loads(resp)
        except ValueError:
            # try to load as YAML
            try:
                r = yaml.safe_load(resp)
            except yaml.YAMLError:
                raise ValueError("No valid spec found")

        # default params for URL interpolation
        TemplateUrl.default = r.get('x-default-params', {})
        # default query parameters for requests
        default_query = r.get('x-default-query', {})
        servers = r.get('servers', [])
        base_path = servers[0].get('url', '') if servers and servers[0] else r.get('basePath', '')
        base_path = base_path.rstrip('/')
        for endpoint, data in r['paths'].items():
            if not endpoint:
                continue
            endpoint = base_path + endpoint
            for key in self._supported_methods:
                try:
                    d = data[key]
                    # If x-monitor is False, skip this
                    if not d.get('x-monitor', True):
                        logging.debug('x-monitor is False, skipping %s %s' % (key, endpoint))
                        continue
                    if key == 'get':
                        default_example = [self.default_request.copy()]
                    else:
                        # Only GETs have default examples
                        default_example = []
                    examples = d.get('x-amples', default_example)
                    for x in examples:
                        req = {'http_method': key}
                        req.update(self.default_request)
                        req.update(x)
                        # Merge query parameters with defaults
                        # In Py 3.5 we could do {**default_query, **query}
                        query = default_query.copy()
                        query.update(req['request'].get('query', {}))
                        req['request']['query'] = query
                        yield endpoint, req
                except KeyError:
                    # No data for this method
                    pass

    def run(self):
        """
        Runs the checks on all the endpoints we find
        """
        res = []
        status = 'OK'
        idx = self.nagios_codes.index(status)
        # Spawn the downloaders
        checks = [{'ep': ep, 'data': data, 'job': gevent.spawn(self._check_endpoint, ep, data)}
                  for ep, data in self.get_endpoints()]
        # The -2 is for terminating the connections before the nrpe timeout
        # kicks in
        gevent.joinall([v['job'] for v in checks], self.nrpe_timeout - 2)

        for v in checks:
            endpoint = v['ep']
            data = v['data']
            title = data.get('title', "test for {}".format(endpoint))
            job = v['job']
            # Endpoint fetching failed or timed out.
            if not job.successful():
                status = 'CRITICAL'
                idx = self.nagios_codes.index(status)
                if job.exception:
                    res.append("{ep} - generic error: {exc}".format(ep=endpoint, exc=job.exception))
                else:
                    res.append(
                        '{ep} ({title}) timed out before a response was received'.format(
                            ep=endpoint, title=title,
                        )
                    )
            else:

                ep_status, msg = job.value
                # WARNING or UNKNOWN
                if ep_status != 'OK':
                    res.append(
                        "{ep} ({title}) is {status}: {message}".format(
                            ep=endpoint, title=title, status=ep_status,
                            message=msg
                        )
                    )
                    ep_idx = self.nagios_codes.index(ep_status)
                    if ep_idx >= idx:
                        status = ep_status
                        idx = ep_idx

        if status == 'OK':
            message = "All endpoints are healthy"
        else:
            message = u"; ".join(res)
        print(message)
        sys.exit(idx)

    def _check_endpoint(self, endpoint, data):
        """
        Actually performs the checks on each single endpoint
        """
        req = data.get('request', {})
        req['http_host'] = self.http_host
        er = EndpointRequest(
            data.get('title',
                     "test for {}".format(endpoint)),
            self._url,
            data['http_method'],
            endpoint,
            req,
            data.get('response'),
            self.metrics_manager
        )
        er.run(self._spawn_downloader(self.is_https, self.insecure))
        return (er.status, er.msg)


class EndpointRequest(object):

    """
    Manages a request to a specific endpoint
    """

    def __init__(self, title, base_url, http_method,
                 endpoint,  request, response, metrics_manager=None):
        """
        Initialize the endpoint request

        Args:
            title (str): a descriptive name

            base_url (str): the base url

            http_method(str): the HTTP method

            endpoint (str): an url template for the endpoint, per RFC 6570

            request (dict): All data for building the request

            response (dict): What we should test in the response

            metrics_manager (Metrics): Instance of Metrics implementation or None. default: None
        """
        self.status = 'OK'
        self.msg = 'Test "{}" healthy'.format(title)
        self.title = title
        self.method = http_method
        self._request(request)
        self._response(response)
        self.tpl_url = TemplateUrl(base_url + endpoint)
        self.base_url = base_url
        if metrics_manager is None:
            self.metrics_manager = NullMetrics()
        else:
            self.metrics_manager = metrics_manager

    def run(self, client):
        """
        Perform the request, and test the result

        Args:
            client (urllib3.Poolmanager): the HTTP client we want to use
        """
        try:
            url = self.tpl_url.realize(self.url_parameters)
            with self.metrics_manager.record(url):
                r = fetch_url(
                    client,
                    url,
                    headers=self.request_headers,
                    fields=self.query_parameters,
                    redirect=False,
                    method=self.method
                )
        except CheckError as e:
            self.status = 'CRITICAL'
            self.msg = "Could not fetch url {}: {}".format(
                url, e)
            return

        # Response status
        if r.status != self.resp_status:
            self.status = "CRITICAL"
            self.msg = ("Test {} returned "
                        "the unexpected status {} (expecting: {})".format(
                            self.title, r.status, self.resp_status))
            return

        # Headers
        for k, v in self.headers.items():
            h = r.getheader(k)
            if h is None or not v(h):
                self.status = "CRITICAL"
                self.msg = ("Test {} had an unexpected value "
                            "for header {}: {}".format(self.title, k, h))
                return
        # Body
        if self.body is not None:
            body = r.data.decode('utf-8')
            if isinstance(self.body, dict) or isinstance(self.body, list):
                data = json.loads(body)
                try:
                    self._check_json_chunk(data, self.body)
                except CheckError:
                    return
                except Exception as e:
                    self.status = "CRITICAL"
                    self.msg = ("Test {} responds with malformed "
                                "body ({}: {}):\n{}".format(
                                    self.title,
                                    e.__class__.__name__,
                                    e.message,
                                    data))
            else:
                check = self._verify(self.body)
                if not check(body):
                    self.status = "WARNING"
                    self.msg = ("Test {} responds with unexpected "
                                "body: {} != {}".format(
                                    self.title,
                                    body,
                                    self.body))
                    return

    def _request(self, data):
        """
        Gather data from the request object
        """
        self.request_headers = {'Host': data['http_host']}
        if 'headers' in data:
            self.request_headers.update(data['headers'])
        self.url_parameters = data.get('params', {})
        qkey = 'query' if self.method == 'get' else 'body'
        self.query_parameters = data.get(qkey, {})

    def _response(self, data):
        """
        Organize the expected response data
        """
        self.resp_status = data['status']
        self.body = data.get('body', None)
        self.headers = {}
        try:
            for k, v in data['headers'].items():
                self.headers[k] = self._verify(v)
        except KeyError:
            pass

    def _verify(self, orig):
        """
        Return a lambda function to verify the response data

        Args:
            arg (str): The argument to check against. If enclosed
                       in slashes, it's assumed to be a regex
        """
        arg = str(orig)
        t = 'eq'
        if arg.startswith('/') and arg.endswith('/'):
            arg = arg.strip('/')
            t = 're'
        if t == 'eq':
            return lambda x: (x == arg) or x.startswith(arg)
        elif t == 're':
            return lambda x: re.search(arg, x)

    def _set_warning(self, prefix, data):
        """
        Sets self.status and self.msg to WARNING with
        an appropriate message, based on the args. If
        the status is set to something other than OK or
        WARNING, it does not update the state, so as
        not to potentially overwrite a CRITICAL message.

        Args:
            prefix (str): the body path being chcked

            data (mixed): the data to use in the message
        """
        if self.status not in ['OK', 'WARNING']:
            return False
        if self.status == 'OK':
            self.msg = ''
        self.status = "WARNING"
        self.msg += ("Test {} responds with unexpected "
                     "value at path {} => {}\n".format(self.title, prefix, data))
        return True

    def _check_json_chunk(self, data, model, prefix=''):
        """
        Recursively check a json chunk of the response.

        Args:
            data (mixed): the data to check

            model (mixed): the model to check the data against

            prefix (str): the depth we're checking at
        """
        if model is None:
            # if the model happens to be None, there is nothing
            # we can say about the validity of the received value
            return True
        elif data is None:
            # assume that means 'empty'
            if type(model).__name__ in ['dict', 'list', 'int', 'float']:
                data = type(model)()
            else:
                data = ''
        if isinstance(model, dict):
            if not isinstance(data, dict):
                self._set_warning(prefix, "Expected dict, "
                                  "gotten a {}".format(type(data).__name__))
                return True
            missing_keys = []
            for k, v in model.items():
                if k not in data:
                    missing_keys.append(k)
                    continue
                p = prefix + '/' + k
                d = data.get(k, None)
                self._check_json_chunk(d, v, prefix=p)
            if len(missing_keys) > 0:
                self._set_warning(prefix,
                                  "Missing keys: {}".format(missing_keys))
        elif isinstance(model, list):
            if not isinstance(data, list):
                self._set_warning(prefix, "Expected list, "
                                  "gotten a {}".format(type(data).__name__))
                return True
            elif len(model) == 1 and len(data) > 1:
                for i in range(len(data)):
                    p = prefix + '[%d]' % i
                    self._check_json_chunk(data[i], model[0], prefix=p)
                return True
            elif len(data) != len(model):
                self._set_warning(prefix, "Expected {} array elements, "
                                  "gotten {}".format(len(model), len(data)))
                return True
            for i in range(len(model)):
                p = prefix + '[%d]' % i
                self._check_json_chunk(data[i], model[i], prefix=p)
        else:
            check = self._verify(model)
            if not check(str(data)):
                self._set_warning(prefix, data)
        return True


class TemplateUrl(object):

    """
    A very partial implementation of RFC 6570, limited to our use
    """
    transforms = {
        'simple': lambda x: x,
        'optional': lambda x: '/' + x,
        'multiple': lambda x: '/'.join(x)
    }
    default = {}
    base = re.compile('(\{.+?\})', re.U)

    def __init__(self, url_string):
        """
        Initialize the template

        Args:
            url_string (str): The url template
        """
        logging.info('Using TemplateUrl, which violates swagger/openapi specification')
        Token = namedtuple('Token', ['key', 'types', 'original'])
        self._url_string = url_string
        self.tokens = []
        for param in self.base.findall(self._url_string):
            types = ['simple']
            key = param.strip('{}')
            if key.startswith('/'):
                types.append('optional')
                key = key.lstrip('/')
            if key.startswith('+'):
                types.append('multiple')
                key = key.lstrip('+')
            self.tokens.append(Token(original=param, key=key, types=types))

    def realize(self, params):
        """
        Returns an url based on the template.

        Args:
            params (dict): the list of params to substitute in the template
        """
        realized = self._url_string
        p = {}
        p.update(self.default)
        p.update(params)
        for token in self.tokens:
            if token.key in p:
                v = p[token.key]
                if isinstance(v, list):
                    v = map(quote_plus, map(str, v))
                else:
                    v = quote_plus(str(v))
                for transform in reversed(token.types):
                    v = self.transforms[transform](v)
            else:
                v = u""
            realized = realized.replace(
                token.original, v, 1)

        return realized


def main():
    parser = argparse.ArgumentParser(
        description='Checks the availability and response of one WMF service')
    parser.add_argument('host_ip', help="The IP address of the host to check")
    parser.add_argument('service_url',
                        help="The base url for the service, including port")
    parser.add_argument('-t', dest="timeout", default=5, type=int,
                        help="Timeout (in seconds) for each "
                        "request. Default: 5")
    parser.add_argument('-s', dest="spec_url", default="/?spec",
                        help="Specific spec url relative to the base one."
                        " Defaults to /?spec.")
    parser.add_argument('-k', dest="insecure",
                        action='store_true',
                        default=False,
                        help="Allow insecure server connections when using SSL."
                        " Defaults to False.")
    args = parser.parse_args()
    metrics_manager = StatsDMetrics(
        host=os.environ.get('STATSD_HOST', default=None),
        port=os.environ.get('STATSD_PORT', default=None),
        prefix=os.environ.get('STATSD_PREFIX', default=None)
    )
    checker = CheckService(args.host_ip, args.service_url,
                           args.timeout, args.spec_url, metrics_manager,
                           args.insecure)
    checker.run()


if __name__ == '__main__':
    main()
