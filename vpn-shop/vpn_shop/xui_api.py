from __future__ import annotations

import http.cookiejar
import json
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class XuiApiError(RuntimeError):
    pass


class XuiApiClient:
    def __init__(self, *, panel_url: str, username: str, password: str, verify_tls: bool) -> None:
        self.panel_url = panel_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self._logged_in = False
        self._csrf_token: str | None = None
        self._lock = threading.RLock()
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[Any] = [urllib.request.HTTPCookieProcessor(self._cookie_jar)]
        if not self.verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        return urllib.request.build_opener(*handlers)

    def _try_toggle_scheme_on_ssl_error(self, exc: Exception) -> bool:
        with self._lock:
            err_str = str(exc).lower()
            if any(token in err_str for token in ("record layer failure", "wrong version number", "unknown protocol", "ssl")):
                if self.panel_url.startswith("https://127.0.0.1") or self.panel_url.startswith("https://localhost"):
                    self.panel_url = "http://" + self.panel_url[len("https://"):]
                    self._opener = self._build_opener()
                    return True
                elif self.panel_url.startswith("http://127.0.0.1") or self.panel_url.startswith("http://localhost"):
                    self.panel_url = "https://" + self.panel_url[len("http://"):]
                    self._opener = self._build_opener()
                    return True
            return False

    def _url(self, path: str) -> str:
        return urllib.parse.urljoin(self.panel_url, path.lstrip("/"))

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        with self._lock:
            data = None
            headers = {
                "Accept": "application/json",
                "User-Agent": "vpn-shop/0.1",
            }
            if self._csrf_token:
                headers["X-Csrf-Token"] = self._csrf_token
                headers["x-csrf-token"] = self._csrf_token
            if payload is not None:
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                headers["Content-Type"] = "application/json; charset=utf-8"

            request = urllib.request.Request(self._url(path), data=data, headers=headers, method=method.upper())
            try:
                with self._opener.open(request, timeout=30) as response:
                    raw = response.read()
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                raise XuiApiError(f"HTTP {exc.code} for {path}: {detail}") from exc
            except urllib.error.URLError as exc:
                if self._try_toggle_scheme_on_ssl_error(exc):
                    return self._request(method, path, payload)
                raise XuiApiError(f"Request failed for {path}: {exc}") from exc

            if not raw:
                # 3x-ui is known to return an empty body for some successful addClient/updateClient calls.
                return {}

            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                return {}
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise XuiApiError(f"Invalid JSON response for {path}: {text}") from exc

    def login(self) -> None:
        with self._lock:
            if self._logged_in:
                return
            if not self.username or not self.password:
                raise XuiApiError("XUI_USERNAME and XUI_PASSWORD must be configured")
            
            # Step 1: Fetch base panel page to obtain session cookies and CSRF token (for 3x-ui v2.4+)
            try:
                req = urllib.request.Request(self.panel_url, headers={"User-Agent": "vpn-shop/0.1"})
                with self._opener.open(req, timeout=15) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    for line in body.splitlines():
                        if "csrf-token" in line:
                            parts = line.split("content=")
                            if len(parts) > 1:
                                token = parts[1].split(">")[0].replace('"', "").replace("'", "").replace("/", "").strip()
                                if token:
                                    self._csrf_token = token
                                    break
            except Exception as exc:
                if self._try_toggle_scheme_on_ssl_error(exc):
                    return self.login()

            response = self._request(
                "POST",
                "/login",
                {"username": self.username, "password": self.password},
            )
            if isinstance(response, dict) and response.get("success") is False:
                raise XuiApiError(response.get("msg") or "3x-ui login failed")
            self._logged_in = True

    @staticmethod
    def _should_retry_after_reauth(path: str, exc: XuiApiError) -> bool:
        message = str(exc)
        if not path.startswith("/panel/api/"):
            return False
        return any(token in message for token in ("HTTP 401", "HTTP 403", "HTTP 404"))

    def _reset_session(self) -> None:
        with self._lock:
            self._logged_in = False
            self._csrf_token = None
            self._cookie_jar.clear()

    def _api(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        with self._lock:
            self.login()
            try:
                return self._request(method, path, payload)
            except XuiApiError as exc:
                if not self._logged_in or not self._should_retry_after_reauth(path, exc):
                    raise
            self._reset_session()
            self.login()
            return self._request(method, path, payload)

    @staticmethod
    def _unwrap(response: Any) -> Any:
        if isinstance(response, dict) and "obj" in response:
            if response.get("success") is False:
                raise XuiApiError(response.get("msg") or "3x-ui API call failed")
            return response["obj"]
        return response

    def get_inbounds(self) -> list[dict[str, Any]]:
        response = self._api("GET", "/panel/api/inbounds/list")
        result = self._unwrap(response)
        if not isinstance(result, list):
            raise XuiApiError("Unexpected inbounds response")
        return result

    def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        try:
            response = self._api("GET", f"/panel/api/inbounds/get/{inbound_id}")
            result = self._unwrap(response)
            if isinstance(result, dict):
                return result
        except XuiApiError:
            pass

        for inbound in self.get_inbounds():
            if int(inbound.get("id") or 0) == int(inbound_id):
                return inbound
        raise XuiApiError(f"Inbound {inbound_id} not found")

    def add_client(self, inbound_id: int, client: dict[str, Any]) -> None:
        self._api(
            "POST",
            "/panel/api/clients/add",
            {
                "client": client,
                "inboundIds": [inbound_id],
            },
        )

    def update_client(self, inbound_id: int, client_key: str, client: dict[str, Any]) -> None:
        self._api(
            "POST",
            f"/panel/api/clients/update/{urllib.parse.quote(client_key, safe='')}",
            {
                "client": client,
                "inboundIds": [inbound_id],
            },
        )

    def delete_client(self, inbound_id: int, client_key: str) -> None:
        response = self._api(
            "POST",
            f"/panel/api/clients/del/{urllib.parse.quote(client_key, safe='')}",
        )
        self._unwrap(response)

    def reset_client_traffic(self, inbound_id: int, email: str) -> None:
        response = self._api(
            "POST",
            f"/panel/api/clients/resetTraffic/{urllib.parse.quote(email, safe='')}",
        )
        self._unwrap(response)

    def restart_xray(self) -> None:
        self._api("POST", "/panel/api/server/restartXrayService")

