import os
import ssl
import tempfile
import threading
from pathlib import Path

from werkzeug.serving import make_server

from app import app

PUBLIC_PORT = int(os.getenv("PUBLIC_PORT", "5000"))
OPERATOR_PORT = int(os.getenv("OPERATOR_PORT", "5443"))


class TransportBindingMiddleware:
    def __init__(self, wsgi_app, verified: bool):
        self.wsgi_app = wsgi_app
        self.verified = verified

    def __call__(self, environ, start_response):
        environ["operator_transport_verified"] = "1" if self.verified else "0"
        return self.wsgi_app(environ, start_response)


def _write_pem_file(name: str, env_var: str) -> str:
    directory = Path(tempfile.gettempdir()) / "cache-me-if-you-ca-gateway-mtls"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(os.environ[env_var], encoding="utf-8")
    return str(path)


def _operator_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=_write_pem_file("server.crt", "GATEWAY_TLS_SERVER_CERT_PEM"),
        keyfile=_write_pem_file("server.key", "GATEWAY_TLS_SERVER_KEY_PEM"),
    )
    context.load_verify_locations(
        cafile=_write_pem_file("client-ca.crt", "GATEWAY_TLS_CLIENT_CA_CERT_PEM")
    )
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _serve(server):
    server.serve_forever()


def main():
    public_server = make_server(
        "0.0.0.0",
        PUBLIC_PORT,
        TransportBindingMiddleware(app.wsgi_app, verified=False),
        threaded=True,
    )
    operator_server = make_server(
        "0.0.0.0",
        OPERATOR_PORT,
        TransportBindingMiddleware(app.wsgi_app, verified=True),
        threaded=True,
        ssl_context=_operator_ssl_context(),
    )
    public_thread = threading.Thread(target=_serve, args=(public_server,), daemon=True)
    operator_thread = threading.Thread(
        target=_serve, args=(operator_server,), daemon=True
    )
    public_thread.start()
    operator_thread.start()
    public_thread.join()
    operator_thread.join()


if __name__ == "__main__":
    main()
