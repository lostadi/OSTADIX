#!/usr/bin/env python3
"""Exercise real OAuth discovery, consent, PKCE, grants, and native MCP calls.

Default mode owns a temporary server and tests durable grants after restart.
--url and --token-file test a deployed server without changing its settings.
Credentials and authorization responses are deliberately never logged.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import secrets
import tempfile
from urllib.parse import parse_qs, urlencode, urlsplit

from smoke_ostadix_mcp_http import (
    Client, EXPECTED_TOOLS, Server, SmokeError, content_object, content_text, require,
)


class HiddenInputs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden" and values.get("name"):
            self.values[str(values["name"])] = values.get("value") or ""


class OAuthProbe:
    def __init__(self, connection_url: str, resource: str, owner: str, timeout: float):
        self.connection = urlsplit(connection_url)
        self.resource = resource
        public = urlsplit(resource)
        self.origin = f"{public.scheme}://{public.netloc}"
        self.authority = public.netloc
        self.issuer = f"{self.origin}/mcp/oauth"
        self.owner = owner
        self.timeout = timeout

    def request(self, method: str, path: str, *, data: dict | None = None,
                form: dict | None = None, headers: dict | None = None):
        outgoing = {"Host": self.authority, "User-Agent": "OSTADIX-MCP/1.0"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            outgoing["Content-Type"] = "application/json"
        if form is not None:
            body = urlencode(form).encode()
            outgoing["Content-Type"] = "application/x-www-form-urlencoded"
        outgoing.update(headers or {})
        cls = (http.client.HTTPSConnection if self.connection.scheme == "https"
               else http.client.HTTPConnection)
        connection = cls(self.connection.hostname, self.connection.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=outgoing)
            response = connection.getresponse()
            raw = response.read().decode("utf-8")
            result_headers = {k.lower(): v for k, v in response.getheaders()}
            try:
                result = json.loads(raw)
            except ValueError:
                result = raw
            return response.status, result_headers, result
        finally:
            connection.close()

    def discover(self) -> None:
        status, headers, _ = self.request("POST", "/mcp", data={"jsonrpc": "2.0", "id": 1,
                                                                          "method": "ping"})
        require(status == 401, "unauthenticated MCP request must return 401")
        require(f'{self.origin}/.well-known/oauth-protected-resource/mcp' in
                headers.get("www-authenticate", ""), "OAuth challenge missing resource metadata")
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"):
            status, _, document = self.request("GET", path)
            require(status == 200 and document.get("resource") == self.resource,
                    "protected resource metadata mismatch")
            require(document.get("authorization_servers") == [self.issuer], "issuer mismatch")
        for path in ("/.well-known/oauth-authorization-server/mcp/oauth",
                     "/.well-known/oauth-authorization-server"):
            status, _, document = self.request("GET", path)
            require(status == 200 and document.get("issuer") == self.issuer, "AS metadata mismatch")
            require("S256" in document.get("code_challenge_methods_supported", []), "S256 not advertised")
            require(document.get("authorization_response_iss_parameter_supported") is True,
                    "RFC 9207 issuer parameter not advertised")
            for key, suffix in (("authorization_endpoint", "authorize"), ("token_endpoint", "token"),
                                ("registration_endpoint", "register")):
                require(document.get(key) == f"{self.issuer}/{suffix}", f"incorrect {key}")
        print("OAuth discovery, resource binding, S256 and RFC 9207 metadata: PASS", flush=True)

    def register(self, redirect: str = "http://127.0.0.1:54321/callback") -> dict:
        status, _, client = self.request("POST", "/mcp/oauth/register", data={
            "client_name": "OSTADIX OAuth qualification",
            "redirect_uris": [redirect],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none",
        })
        require(status == 201 and bool(client.get("client_id")), "public client registration failed")
        return client

    def authorization_form(self, client: dict, *, extra: dict | None = None):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = {
            "client_id": client["client_id"], "redirect_uri": client["redirect_uris"][0],
            "response_type": "code", "scope": "ostadix:execute", "resource": self.resource,
            "state": secrets.token_urlsafe(24), "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query.update(extra or {})
        status, headers, html = self.request("GET", "/mcp/oauth/authorize?" + urlencode(query))
        return verifier, query, status, headers, html

    def authorize(self, client: dict, *, deny: bool = False,
                  redirect_uri: str | None = None) -> tuple[str, str, dict]:
        verifier, query, status, headers, html = self.authorization_form(
            client, extra={"redirect_uri": redirect_uri} if redirect_uri else None)
        require(status == 200 and isinstance(html, str), "consent form unavailable")
        parser = HiddenInputs()
        parser.feed(html)
        require(bool(parser.values.get("csrf")), "consent form missing CSRF nonce")
        cookie = headers.get("set-cookie", "").split(";", 1)[0]
        require(bool(cookie), "consent form missing CSRF cookie")
        fields = {**parser.values, "owner_token": self.owner, "decision": "deny" if deny else "allow"}
        status, headers, _ = self.request("POST", "/mcp/oauth/authorize", form=fields,
                                          headers={"Cookie": cookie, "Origin": self.origin})
        require(status in (302, 303), "consent did not redirect")
        redirected = urlsplit(headers.get("location", ""))
        require(f"{redirected.scheme}://{redirected.netloc}{redirected.path}" == query["redirect_uri"],
                "consent used an unregistered redirect")
        response = parse_qs(redirected.query)
        require(response.get("state") == [query["state"]], "OAuth state not preserved")
        require(response.get("iss") == [self.issuer], "OAuth redirect issuer missing/mismatched")
        if deny:
            require(response.get("error") == ["access_denied"] and "code" not in response,
                    "denied consent returned a code")
            return "", verifier, query
        require(bool(response.get("code")), "consent omitted authorization code")
        return response["code"][0], verifier, query

    def exchange(self, client: dict, code: str, verifier: str, **changes):
        fields = {"grant_type": "authorization_code", "client_id": client["client_id"],
                  "code": code, "code_verifier": verifier, "resource": self.resource,
                  "redirect_uri": client["redirect_uris"][0]}
        fields.update(changes)
        return self.request("POST", "/mcp/oauth/token", form=fields)

    def issue(self, client: dict) -> dict:
        code, verifier, _ = self.authorize(client)
        status, _, tokens = self.exchange(client, code, verifier)
        require(status == 200 and bool(tokens.get("access_token")) and bool(tokens.get("refresh_token")),
                "OAuth code exchange failed")
        return tokens

    def mcp(self, token: str) -> Client:
        probe = self

        class BoundClient(Client):
            def request(self, method, payload=None, *, path="/mcp", headers=None):
                return super().request(method, payload, path=path,
                                       headers={"Host": probe.authority, "User-Agent": "OSTADIX-MCP/1.0",
                                                **(headers or {})})

        return BoundClient(self.connection.geturl(), token, self.timeout)

    def refresh(self, client: dict, token: str):
        return self.request("POST", "/mcp/oauth/token", form={
            "grant_type": "refresh_token", "client_id": client["client_id"],
            "refresh_token": token, "resource": self.resource,
        })

    def revoke(self, client: dict, token: str) -> None:
        status, _, _ = self.request("POST", "/mcp/oauth/revoke", form={
            "client_id": client["client_id"], "token": token,
        })
        require(status == 200, "token revocation failed")

    def run(self, restart=None, alternate_resource: str | None = None) -> None:
        self.discover()
        for redirect in ("https://example.com/cb#fragment", "javascript:alert(1)",
                         "http://example.com/cb", "https://name:password@example.com/cb"):
            status, _, _ = self.request("POST", "/mcp/oauth/register", data={"redirect_uris": [redirect]})
            require(status == 400, "unsafe client redirect accepted")
        client = self.register()
        # Native apps reserve their callback port at login time (RFC 8252).
        for host in ("127.0.0.1", "localhost"):
            loopback = self.register(f"http://{host}/callback")
            actual_redirect = f"http://{host}:54322/callback"
            loop_code, loop_verifier, _ = self.authorize(loopback, redirect_uri=actual_redirect)
            status, _, loop_tokens = self.exchange(loopback, loop_code, loop_verifier,
                                                   redirect_uri=actual_redirect)
            require(status == 200, "registered loopback redirect did not accept its selected port")
            self.revoke(loopback, loop_tokens["refresh_token"])
        _, _, status, headers, html = self.authorization_form(client)
        require(status == 200, "CSRF probe form unavailable")
        parsed = HiddenInputs()
        parsed.feed(html)
        fields = {**parsed.values, "decision": "allow", "owner_token": self.owner}
        cookie = headers.get("set-cookie", "").split(";", 1)[0]
        status, _, _ = self.request("POST", "/mcp/oauth/authorize", form=fields,
                                    headers={"Cookie": cookie, "Origin": "https://untrusted.example"})
        require(status == 403, "cross-origin consent submission accepted")
        status, _, _ = self.request("POST", "/mcp/oauth/authorize", form=fields,
                                    headers={"Origin": self.origin})
        require(status == 403, "consent accepted without the browser CSRF cookie")
        code, verifier, _ = self.authorize(client)
        for changes in ({"code_verifier": "wrong" * 12},
                        {"resource": "https://other.example/mcp"},
                        {"redirect_uri": "http://127.0.0.1:54321/wrong"}):
            actual_verifier = changes.pop("code_verifier", verifier)
            status, _, _ = self.exchange(client, code, actual_verifier, **changes)
            require(status == 400, "code accepted with incorrect verifier/resource/redirect")
        status, _, tokens = self.exchange(client, code, verifier)
        require(status == 200, "valid code failed after rejected exchanges")
        principal = self.mcp(tokens["access_token"])
        principal.initialize("2025-11-25")
        require({t["name"] for t in principal.rpc("tools/list")["tools"]} == EXPECTED_TOOLS,
                "OAuth changed MCP tool inventory")
        value = content_object(principal.tool("o_execute", {"source": "python^( __oval_result__ = 6 * 7 )_python\n"}))
        require(value.get("result", {}).get("value") == {"t": "number", "v": {"kind": "int", "v": "42"}},
                "OAuth native execution result differs")
        require("SMOKE_OK" in content_text(principal.tool("o_smoke")), "OAuth native smoke failed")
        if alternate_resource:
            alternate = OAuthProbe(self.connection.geturl(), alternate_resource, self.owner, self.timeout)
            status, _, _ = alternate.mcp(tokens["access_token"]).request("POST", {"method": "ping"})
            require(status == 401, "OAuth token crossed into a different configured resource")
        print("OAuth consent, PKCE, exact 21 tools, native result 42 and smoke: PASS", flush=True)

        other_tokens = self.issue(client)
        other = self.mcp(other_tokens["access_token"])
        other.session, other.version = principal.session, principal.version
        status, _, _ = other.request("POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        require(status == 404, "a different grant adopted another grant's MCP session")
        status, _, rotated = self.refresh(client, tokens["refresh_token"])
        require(status == 200 and rotated["refresh_token"] != tokens["refresh_token"], "refresh did not rotate")
        principal.token = rotated["access_token"]
        require(bool(principal.rpc("tools/list")["tools"]), "refresh lost its own MCP session")
        principal.delete()
        self.revoke(client, other_tokens["refresh_token"])
        require(self.mcp(other_tokens["access_token"]).request("POST", {"method": "ping"})[0] == 401,
                "revoked grant still authenticates")
        self.authorize(client, deny=True)
        print("OAuth grant/session isolation, refresh continuity, revocation and denied consent: PASS", flush=True)

        if restart is not None:
            self.connection = urlsplit(restart())
            persisted = self.mcp(rotated["access_token"])
            persisted.initialize("2025-11-25")
            require(bool(persisted.rpc("tools/list")["tools"]), "grant did not survive server restart")
            persisted.delete()
            print("OAuth registrations and grants survive a server restart: PASS", flush=True)
        status, _, _ = self.refresh(client, tokens["refresh_token"])
        require(status == 400, "spent refresh token was reused")
        require(self.mcp(rotated["access_token"]).request("POST", {"method": "ping"})[0] == 401,
                "refresh replay did not revoke its descendants")
        status, _, _ = self.exchange(client, code, verifier)
        require(status == 400, "authorization code replay accepted")
        print("Authorization code replay and refresh-family replay rejection: PASS", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--server", type=Path)
    parser.add_argument("--url", help="Verify an existing HTTPS endpoint instead of a temporary server")
    parser.add_argument("--token-file", type=Path, help="Owner credential for --url; never printed")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.url:
        if not args.token_file or not args.url.startswith("https://") or not args.url.endswith("/mcp"):
            parser.error("--url requires an HTTPS /mcp URL and --token-file")
        OAuthProbe(args.url, args.url, args.token_file.read_text().strip(), args.timeout).run()
        return
    root = args.root.resolve()
    binary = (args.server or root / "mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp").resolve()
    with tempfile.TemporaryDirectory(prefix="ostadix-oauth-smoke-") as directory:
        state = Path(directory)
        owner = secrets.token_urlsafe(48)
        credential = state / "owner.token"
        credential.write_text(owner)
        credential.chmod(0o600)
        resource = "https://ostadix-oauth.example/mcp"
        arguments = ["--token-file", str(credential), "--oauth-public-url", resource,
                     "--oauth-public-url", "https://ostadix-alternate.example/mcp",
                     "--oauth-state-dir", str(state / "oauth")]
        server = Server(binary, root, arguments, args.timeout)

        def restart() -> str:
            nonlocal server
            server.stop()
            server = Server(binary, root, arguments, args.timeout)
            return server.ready()

        try:
            OAuthProbe(server.ready(), resource, owner, args.timeout).run(
                restart, alternate_resource="https://ostadix-alternate.example/mcp")
        finally:
            server.stop()
    print("Ostadix MCP OAuth smoke: PASS")


if __name__ == "__main__":
    try:
        main()
    except (SmokeError, OSError, ValueError) as error:
        raise SystemExit(f"OAuth smoke failed: {error}") from error
