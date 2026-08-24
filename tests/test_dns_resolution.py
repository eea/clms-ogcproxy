import asyncio
import importlib
import os
import sys
import types
import unittest


def import_ogcproxy():
    for name in [
        "ogcproxy",
        "fastapi",
        "httpcore",
        "redis",
        "redis.asyncio",
        "dns",
        "dns.resolver",
    ]:
        sys.modules.pop(name, None)

    fastapi = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code, detail):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    class FastAPI:
        def get(self, *_args, **_kwargs):
            def decorator(func):
                return func

            return decorator

    fastapi.FastAPI = FastAPI
    fastapi.HTTPException = HTTPException
    fastapi.Request = object
    sys.modules["fastapi"] = fastapi

    httpcore = types.ModuleType("httpcore")

    class AsyncNetworkBackend:
        pass

    class AnyIOBackend:
        async def connect_tcp(self, *_args, **_kwargs):
            raise AssertionError("default network backend should not be used")

        async def connect_unix_socket(self, *_args, **_kwargs):
            raise AssertionError("unix socket should not be used")

        async def sleep(self, *_args, **_kwargs):
            return None

    class AsyncConnectionPool:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    httpcore.AsyncNetworkBackend = AsyncNetworkBackend
    httpcore.AnyIOBackend = AnyIOBackend
    httpcore.AsyncConnectionPool = AsyncConnectionPool
    sys.modules["httpcore"] = httpcore

    httpx = types.ModuleType("httpx")
    sys.modules["httpx"] = httpx

    redis = types.ModuleType("redis")
    redis_asyncio = types.ModuleType("redis.asyncio")

    class FakeRedis:
        async def set(self, *_args, **_kwargs):
            return None

        async def exists(self, *_args, **_kwargs):
            return False

        async def ping(self):
            return True

    redis_asyncio.from_url = lambda *_args, **_kwargs: FakeRedis()
    redis.asyncio = redis_asyncio
    sys.modules["redis"] = redis
    sys.modules["redis.asyncio"] = redis_asyncio

    dns = types.ModuleType("dns")
    dns_resolver = types.ModuleType("dns.resolver")

    class NoAnswer(Exception):
        pass

    class NXDOMAIN(Exception):
        pass

    class LifetimeTimeout(Exception):
        pass

    class NoNameservers(Exception):
        pass

    class Resolver:
        def __init__(self, *_args, **_kwargs):
            self.nameservers = []

        def resolve(self, *_args, **_kwargs):
            raise NoAnswer()

    dns_resolver.NoAnswer = NoAnswer
    dns_resolver.NXDOMAIN = NXDOMAIN
    dns_resolver.LifetimeTimeout = LifetimeTimeout
    dns_resolver.NoNameservers = NoNameservers
    dns_resolver.Resolver = Resolver
    dns.resolver = dns_resolver
    sys.modules["dns"] = dns
    sys.modules["dns.resolver"] = dns_resolver

    return importlib.import_module("ogcproxy")


class DNSResolutionTests(unittest.TestCase):
    def test_proxy_dns_defaults_to_cloudflare_resolver(self):
        os.environ.pop("PROXY_DNS", None)
        ogcproxy = import_ogcproxy()

        self.assertEqual(ogcproxy.PROXY_DNS, ["1.1.1.1"])

    def test_proxy_dns_can_be_overridden_from_environment(self):
        os.environ["PROXY_DNS"] = "9.9.9.9"
        try:
            ogcproxy = import_ogcproxy()
        finally:
            os.environ.pop("PROXY_DNS", None)

        self.assertEqual(ogcproxy.PROXY_DNS, ["9.9.9.9"])

    def test_configured_nameservers_use_dns_library_not_system_dns(self):
        ogcproxy = import_ogcproxy()

        class Answer:
            def __init__(self, value):
                self.value = value

            def to_text(self):
                return self.value

        class Resolver:
            instance = None

            def __init__(self, *_args, **_kwargs):
                Resolver.instance = self
                self.nameservers = []
                self.timeout = None
                self.lifetime = None
                self.calls = []

            def resolve(self, hostname, record_type):
                self.calls.append((hostname, record_type))
                if record_type == "A":
                    return [Answer("93.184.216.34")]
                raise ogcproxy.dns.resolver.NoAnswer()

        ogcproxy.dns.resolver.Resolver = Resolver
        ips = ogcproxy.resolve_hostname_ips("land.copernicus.eu")

        self.assertEqual(ips, ["93.184.216.34"])
        self.assertEqual(Resolver.instance.nameservers, ["1.1.1.1"])
        self.assertEqual(
            Resolver.instance.calls,
            [("land.copernicus.eu", "A"), ("land.copernicus.eu", "AAAA")],
        )

    def test_any_private_resolved_address_is_rejected(self):
        ogcproxy = import_ogcproxy()

        with self.assertRaises(ogcproxy.HTTPException) as raised:
            ogcproxy.validate_public_ips(["93.184.216.34", "10.0.0.5"])

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail, "Private IP not allowed")

    def test_network_backend_connects_to_validated_ip(self):
        ogcproxy = import_ogcproxy()
        connected = []

        class FakeBackend:
            async def connect_tcp(
                self,
                host,
                port,
                timeout=None,
                local_address=None,
                socket_options=None,
            ):
                connected.append((host, port, timeout, local_address, socket_options))
                return "stream"

            async def connect_unix_socket(self, path, timeout=None, socket_options=None):
                raise AssertionError("unexpected unix socket")

            async def sleep(self, seconds):
                return None

        backend = ogcproxy.ValidatingAsyncNetworkBackend(
            resolver=lambda hostname: ["93.184.216.34"],
            network_backend=FakeBackend(),
        )

        result = asyncio.run(
            backend.connect_tcp(
                "land.copernicus.eu",
                443,
                timeout=5,
                local_address="0.0.0.0",
                socket_options=[("level", "optname", "value")],
            )
        )

        self.assertEqual(result, "stream")
        self.assertEqual(
            connected,
            [
                (
                    "93.184.216.34",
                    443,
                    5,
                    "0.0.0.0",
                    [("level", "optname", "value")],
                )
            ],
        )

    def test_ogc_check_propagates_private_ip_guard_errors(self):
        ogcproxy = import_ogcproxy()

        async def raise_guard_error(*_args, **_kwargs):
            raise ogcproxy.HTTPException(403, "Private IP not allowed")

        ogcproxy.fetch_get = raise_guard_error

        with self.assertRaises(ogcproxy.HTTPException) as raised:
            asyncio.run(ogcproxy.is_ogc_service("https://land.copernicus.eu/wms", {}))

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail, "Private IP not allowed")


if __name__ == "__main__":
    unittest.main()
