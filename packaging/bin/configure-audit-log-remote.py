#!/usr/bin/python3
"""Safely configure remote forwarding for oVirt Engine audit logs."""

import argparse
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


CONFIG_FILE = Path("/etc/rsyslog.d/ovworks-audit-remote.conf")
RSYSLOGD = "/usr/sbin/rsyslogd"
SYSTEMCTL = "/bin/systemctl"
HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                      r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class RemoteConfigError(RuntimeError):
    """An expected and safe-to-display configuration failure."""


def normalize_target(value):
    value = (value or "").strip()
    if not value or any(character.isspace() for character in value):
        raise RemoteConfigError("원격 서버 주소 형식이 올바르지 않습니다.")

    host = value
    port = None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise RemoteConfigError("원격 서버 IPv6 주소 형식이 올바르지 않습니다.")
        host = value[1:closing]
        remainder = value[closing + 1:]
        if remainder:
            if not remainder.startswith(":"):
                raise RemoteConfigError("원격 서버 주소 형식이 올바르지 않습니다.")
            port = remainder[1:]
        try:
            ipaddress.IPv6Address(host)
        except ValueError as error:
            raise RemoteConfigError("원격 서버 IPv6 주소가 올바르지 않습니다.") from error
        host = "[%s]" % host
    else:
        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
        elif ":" in value:
            raise RemoteConfigError("IPv6 주소는 [주소]:포트 형식으로 입력해 주세요.")
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            if not HOSTNAME.fullmatch(host):
                raise RemoteConfigError("원격 서버 호스트명이 올바르지 않습니다.")

    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise RemoteConfigError("원격 서버 포트는 1~65535 범위여야 합니다.")
        return "%s:%s" % (host, int(port))
    return host


def render_config(target):
    host, port = target_host_and_port(target)
    return ("module(load=\"imfile\")\n"
            "input(\n"
            "type=\"imfile\"\n"
            "File=\"/var/log/ovirt-engine/*.log\"\n"
            "Tag=\"ovirt-engine:\"\n"
            "Facility=\"local0\"\n"
            "Severity=\"info\"\n"
            "PersistStateInterval=\"100\"\n"
            "reopenOnTruncate=\"on\"\n"
            "freshStartTail=\"on\"\n"
            "addMetadata=\"on\"\n"
            ")\n"
            "action(\n"
            "type=\"omfwd\"\n"
            "Target=\"%s\"\n"
            "Port=\"%s\"\n"
            "Protocol=\"tcp\"\n"
            "KeepAlive=\"on\"\n"
            "Action.ResumeRetryCount=\"-1\"\n"
            "queue.type=\"LinkedList\"\n"
            "queue.filename=\"ovirt_remote\"\n"
            "queue.maxdiskspace=\"2g\"\n"
            "queue.saveonshutdown=\"on\"\n"
            ")\n" % (host, port))


def target_host_and_port(target):
    if target.startswith("["):
        closing = target.index("]")
        host = target[1:closing]
        remainder = target[closing + 1:]
        return host, remainder[1:] if remainder else "514"
    if target.count(":") == 1:
        return tuple(target.rsplit(":", 1))
    return target, "514"


def unlink_if_exists(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def configure(target):
    target = normalize_target(target)
    CONFIG_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    previous = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else None
    descriptor, temporary_name = tempfile.mkstemp(prefix=".%s." % CONFIG_FILE.name,
                                                   dir=str(CONFIG_FILE.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(render_config(target))
        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(CONFIG_FILE))
        validation = subprocess.run([RSYSLOGD, "-N1"], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, check=False)
        if validation.returncode != 0:
            raise RemoteConfigError("rsyslog 설정 검증 실패: %s" % validation.stdout.strip())
        restart = subprocess.run([SYSTEMCTL, "restart", "rsyslog"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, check=False)
        if restart.returncode != 0:
            raise RemoteConfigError("rsyslog 재시작 실패: %s" % restart.stdout.strip())
    except (OSError, RemoteConfigError) as error:
        if previous is None:
            unlink_if_exists(CONFIG_FILE)
        else:
            CONFIG_FILE.write_bytes(previous)
        if isinstance(error, RemoteConfigError):
            raise
        raise RemoteConfigError("원격 백업 설정 실패: %s" % error) from error
    finally:
        unlink_if_exists(temporary)
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    args = parser.parse_args(argv)
    try:
        target = configure(args.target)
        print("SUCCESS: %s" % target)
    except RemoteConfigError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
