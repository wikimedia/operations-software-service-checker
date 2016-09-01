service-checker documentation
=============================

A generic swagger-based webservice checker.

It can perform http requests based on the ``x-amples`` sections of the
``paths`` part of the spec, and match responses to what the expected
response is. It is able to check both headers and the body of the response.

Installation
------------

This software is known to work correctly with python 2.7 and 3.5

From Source
~~~~~~~~~~~

.. code:: bash

    $ python setup.py install

Usage
-----

Once installed, you will have the ``service-checker-swagger`` binary
in your path.

Suppose you have a webservice running on localhost port 8080, which
reponds for HTTP host ``awesomeservice.local`` and it
exposes its swagger spec on the /swagger url. To check it is working
as designed according to its spec you can just do

.. code:: bash

    $ service-checker-swagger 127.0.0.1 awesomeservice.local:8080 -s /swagger
    All endpoints are healthy


Spec format support
-------------------

``service-checker-swagger`` checks each of the paths in your swagger/OpenAPI
specification for an ``x-amples`` section and uses it to do live requests
to the API and checks that the response corresponds to the base. The
``x-amples`` section is an extension to the swagger spec that has been
introduced by `swagger-test <https://github.com/earldouglas/swagger-test>`_
and that consists of items with ``request`` and ``response`` sections.

Url templating according to RFC 6570 is partially supported via the
``params`` section of the ``x-amples`` section.

There could be some specific examples you might want to run unit tests
on but you don't want to monitor on a live service (typically, any
non-idempotent request is a good candidate for this). In that case,
just add ``x-monitor: false`` at the root of your example.

Basic example
~~~~~~~~~~~~~
.. code:: javascript

   "/pets/{id}": {
       "get": {
          "x-monitor": true,
          "x-amples": [ {
            "request": {
              "params": {"id": 10},
              "headers": { "Accept": "application/json", },
              "query": {"refresh": "y"},
            },
            "response": {
              "status": 200,
              "headers": {"X-Pet-Iscute": "yes"},
              "body": { "species": "/canis .*/"}
            },
            ...

Url template interpolation
~~~~~~~~~~~~~~~~~~~~~~~~~~

We support basic Url template interpolation, a subset of the
specification in RFC 6570 is supported at the moment. We support
simple, optional and multiple parameter substitutions.



Body data check
~~~~~~~~~~~~~~~

Body data is assumed to be either json or plain text; actual content
(of either fields in the json structure or the text) can be either
matched exactly or with a regexp. So for example:

.. code:: javascript

    "body": "abcd"

will verify that "abcd" is the exact response body, while

.. code:: javascript

    "body": "/^abcd/"

will just check that the body begins with "abcd".

Limitations
-----------

- Only supports GET and POST at the moment
- Only plain-text and json responses are supported
- Url templating support is pretty limited at the moment
- All endpoints are checked sequentially, which could easily lead to
  timeouts in nagios-like systems
- No logging
