"""
NIDS entrypoint. Wires Analyzer -> Sniffer -> Responder -> Flask + SocketIO.

Usage (must be root for packet capture):
    sudo .venv/bin/python main.py --interface eth0 --port 5000

Dashboard: http://localhost:5000
"""

import argparse
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

import config
import db.models  # noqa: F401  -- registers ORM models on Base
from api.config_routes import config_bp
from api.routes import api_bp
from api.websocket import attach as attach_websocket
from core.analyzer import Analyzer
from core.responder import Responder
from core.sniffer import PacketSniffer
from db.database import Base, engine


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Network Intrusion Detection System")
    p.add_argument("--interface", "-i", default=config.NETWORK_INTERFACE,
                   help="NIC name (default from config.py)")
    p.add_argument("--port", "-p", type=int, default=config.FLASK_PORT,
                   help="Flask port")
    p.add_argument("--host", default=config.FLASK_HOST, help="Flask bind host")
    return p.parse_args()


def create_app() -> tuple[Flask, SocketIO]:
    project_root = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "dashboard" / "templates"),
        static_folder=str(project_root / "dashboard" / "static"),
    )
    app.config["SECRET_KEY"] = "nids-midterm-secret"
    app.register_blueprint(api_bp)
    app.register_blueprint(config_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/settings")
    def settings():
        return render_template("settings.html")

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
    return app, socketio


def main() -> None:
    args = parse_args()
    config.NETWORK_INTERFACE = args.interface
    config.FLASK_PORT = args.port
    config.FLASK_HOST = args.host

    Base.metadata.create_all(engine)

    app, socketio = create_app()
    emit_alert = attach_websocket(socketio)

    responder = Responder(socket_emit=emit_alert)
    analyzer = Analyzer()
    sniffer = PacketSniffer(
        analyzer=analyzer,
        alert_sink=responder.handle_alert,
        blocked_ips=responder.blocked_ips,  # dùng chung set, không cần copy/sync
    )
    sniffer.start()

    # Store in app.extensions so API routes can call unblock() / clear_cooldown()
    app.extensions["responder"] = responder
    app.extensions["analyzer"] = analyzer

    print(f"[NIDS] sniffing on {config.NETWORK_INTERFACE}")
    print(f"[NIDS] dashboard at http://{config.FLASK_HOST}:{config.FLASK_PORT}")

    socketio.run(
        app,
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        allow_unsafe_werkzeug=True,  # required for SocketIO + threading mode
    )


if __name__ == "__main__":
    main()

    # TODO: learn iptables, 