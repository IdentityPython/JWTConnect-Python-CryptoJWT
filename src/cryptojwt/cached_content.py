import json
import logging
import os
import threading
import time
from abc import ABC
from abc import abstractmethod
from datetime import datetime
from typing import Callable
from typing import List
from typing import Optional

import requests

from cryptojwt.jwk import JWK
from cryptojwt.jwk.jwk import key_from_jwk_dict

from .exception import UpdateFailed
from .utils import httpc_params_loader

DEFAULT_CACHE_TIME = 300


def jwks_deserializer(data) -> List[JWK]:
    keys = json.loads(data)
    if isinstance(keys, dict) and "keys" in keys:
        return [key_from_jwk_dict(k) for k in keys["keys"]]
    elif isinstance(keys, list):
        return [key_from_jwk_dict(k) for k in keys]
    raise ValueError("Unknown JWKS format")


class NotModified(Exception):
    pass


class CachedContent(ABC):
    def __init__(
        self,
        source: str,
        cache_time: int = DEFAULT_CACHE_TIME,
        ignore_errors_period: int = 0,
        deserializer: Optional[Callable] = None,
        **kwargs,
    ):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.lock = threading.Lock()
        self.source = source
        self.cache_time = cache_time
        self.ignore_errors_period = ignore_errors_period
        self.ignore_errors_until = None
        self.last_update = None
        self.next_update = 0
        self.deserializer = deserializer or (lambda x: x)
        self.content = None

    def update(self, force: bool = False, fatal: bool = False) -> bool:
        """Update last cached content, return True if updated"""
        if not force and time.time() < self.next_update:
            return False
        with self.lock:
            if self.ignore_errors_until and time.time() < self.ignore_errors_until:
                self.logger.warning(
                    "Skip updating content from %s (in error holddown until %s)",
                    self.source,
                    datetime.fromtimestamp(self.ignore_errors_until),
                )
            else:
                try:
                    content = self.read_content(force=force)
                    self.content = self.deserializer(content)
                    self.last_update = time.time()
                    self.next_update = self.last_update + self.cache_time
                    self.ignore_errors_until = None
                except NotModified:
                    return False
                except Exception as exc:
                    self.logger.error("Content update %s failed: %s", self.source, exc)
                    if self.ignore_errors_period:
                        self.ignore_errors_until = time.time() + self.ignore_errors_period
                    if fatal:
                        raise UpdateFailed(str(exc))
                    return False
        return True

    def get(self, update: bool = False, force: bool = False, **kwargs):
        """Get last cached content, update if requested to"""
        if update or force or self.content is None:
            self.update(force=force, **kwargs)
        return self.content

    @abstractmethod
    def read_content(self, force: bool = False):
        pass

    @classmethod
    def from_source(cls, source: str, **kwargs):
        if source.startswith("http://") or source.startswith("https://"):
            return CachedContentHTTP(url=source, **kwargs)
        else:
            return CachedContentFile(filename=source, **kwargs)


class CachedContentFile(CachedContent):
    def __init__(self, filename: str, **kwargs):
        super().__init__(source=filename, **kwargs)
        self.filename = filename
        self.last_modified = None

    def read_content(self, force: bool = False):
        last_modified = os.stat(self.filename).st_mtime
        if not force:
            if last_modified == self.last_modified:
                self.logger.debug("%s not modified since last refresh", self.filename)
                raise NotModified
        else:
            self.logger.debug("Refresh forced")
        self.logger.debug("%s modified", self.filename)
        self.last_modified = last_modified
        with open(self.filename) as file:
            t1 = time.perf_counter()
            content = file.read()
            t2 = time.perf_counter()
            self.logger.info(
                "Load for %s took %.3f seconds",
                self.filename,
                t2 - t1,
                extra={
                    "filename": self.filename,
                    "content_length": len(content),
                    "last_modified": self.last_modified,
                    "duration": t2 - t1,
                },
            )
        return content


class CachedContentHTTP(CachedContent):
    def __init__(
        self,
        url: str,
        httpc=None,
        httpc_params=None,
        **kwargs,
    ):
        super().__init__(source=url, **kwargs)
        self.url = url
        self.http_etag = None
        self.http_date = None
        self.httpc = httpc if httpc else requests.request
        self.httpc_params = httpc_params_loader(httpc_params)

    def read_content(self, force: bool = False):
        """Refresh content fetched via HTTP"""
        httpc_params = self.httpc_params.copy()
        if "headers" not in httpc_params:
            httpc_params["headers"] = {}
        if not force:
            if self.http_etag:
                httpc_params["headers"]["If-None-Match"] = self.http_etag
            elif self.http_date:
                httpc_params["headers"]["If-Modified-Since"] = self.http_date
        t1 = time.perf_counter()
        response = self.httpc("GET", self.url, **httpc_params)
        t2 = time.perf_counter()
        self.logger.info(
            "GET for %s took %.3f seconds",
            self.url,
            t2 - t1,
            extra={
                "url": self.url,
                "content_length": len(response.content),
                "last_modified": response.headers.get("date"),
                "http_status": response.status_code,
                "duration": t2 - t1,
            },
        )
        response.raise_for_status()
        if response.status_code == 304:
            raise NotModified
        self.http_etag = response.headers.get("etag")
        self.http_date = response.headers.get("date")
        self.logger.debug("%s updated", self.url)
        return response.text
