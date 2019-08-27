from datetime import datetime
from contextlib import contextmanager
from gevent import monkey; monkey.patch_all()  # noqa
import gevent
import statsd
import urllib3


class Metrics:
    """ Metrics base class """

    @contextmanager
    def record(self, url):
        """ Context manager that gathers tags and wall clock time delta """
        tags = self._get_tags_for(url)
        start = datetime.utcnow()
        yield
        delta = datetime.utcnow() - start
        self.send(delta, tags)

    def send(self, delta, tags):
        """ Emits the metric """
        raise NotImplementedError

    def _get_tags_for(self, url):
        """ Builds tags to be sent along with the metric """
        raise NotImplementedError


class Null(Metrics):
    """ No-operation metrics implementation """

    def send(self, delta, tags):
        pass

    def _get_tags_for(self, url):
        return None


class StatsD(Metrics):
    """ StatsD metrics implementation """

    def __init__(self, **config):
        host = config.get('host')
        port = config.get('port')
        self.prefix = config.get('prefix')
        self.client = None
        if None not in [host, port, self.prefix]:
            self.client = statsd.StatsClient(host, port)

    def send(self, delta, tags):
        if self.client is not None:
            try:
                gevent.spawn(self.client.timing, tags, delta.total_seconds() * 1000)
            except Exception:
                # Statsd reporting is a secondary function of this code: if it fails, we're ok
                # with it and it should not interfere with completing the checks.
                pass

    def _get_tags_for(self, url):
        url = urllib3.util.parse_url(url)
        return "{prefix}.{tags}".format(
            prefix=self.prefix,
            tags=url.path.replace('.', '_').replace('/', '', 1).replace('/', '_')
        )
