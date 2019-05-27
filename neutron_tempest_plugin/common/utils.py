# Copyright 2011, VMware, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Borrowed from nova code base, more utilities will be added/borrowed as and
# when needed.

"""Utilities and helper functions."""

import functools
import threading
import time
try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse

import eventlet

SCHEMA_PORT_MAPPING = {
    "http": 80,
    "https": 443,
}


class classproperty(object):
    def __init__(self, f):
        self.func = f

    def __get__(self, obj, owner):
        return self.func(owner)


class WaitTimeout(Exception):
    """Default exception coming from wait_until_true() function."""


class LockWithTimer(object):
    def __init__(self, threshold):
        self._threshold = threshold
        self.timestamp = 0
        self._lock = threading.Lock()

    def acquire(self):
        return self._lock.acquire(False)

    def release(self):
        return self._lock.release()

    def time_to_wait(self):
        return self.timestamp - time.time() + self._threshold


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    """Wait until callable predicate is evaluated as True

    :param predicate: Callable deciding whether waiting should continue.
    Best practice is to instantiate predicate with functools.partial()
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    :param exception: Exception instance to raise on timeout. If None is passed
                      (default) then WaitTimeout exception is raised.
    """
    try:
        with eventlet.Timeout(timeout):
            while not predicate():
                eventlet.sleep(sleep)
    except eventlet.Timeout:
        if exception is not None:
            # pylint: disable=raising-bad-type
            raise exception
        raise WaitTimeout("Timed out after %d seconds" % timeout)


# TODO(haleyb): move to neutron-lib
# code copied from neutron repository - neutron/tests/base.py
def unstable_test(reason):
    def decor(f):
        @functools.wraps(f)
        def inner(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except Exception as e:
                msg = ("%s was marked as unstable because of %s, "
                       "failure was: %s") % (self.id(), reason, e)
                raise self.skipTest(msg)
        return inner
    return decor


def override_class(overriden_class, overrider_class):
    """Override class definition with a MixIn class

    If overriden_class is not a subclass of overrider_class then it creates
    a new class that has as bases overrider_class and overriden_class.
    """

    if not issubclass(overriden_class, overrider_class):
        name = overriden_class.__name__
        bases = (overrider_class, overriden_class)
        overriden_class = type(name, bases, {})
    return overriden_class


def normalize_url(url):
    """Normalize url without port with schema default port

    """
    parse_result = urlparse.urlparse(url)
    (scheme, netloc, url, params, query, fragment) = parse_result
    port = parse_result.port
    if scheme in SCHEMA_PORT_MAPPING and not port:
        netloc = netloc + ":" + str(SCHEMA_PORT_MAPPING[scheme])
    return urlparse.urlunparse((scheme, netloc, url, params, query, fragment))
