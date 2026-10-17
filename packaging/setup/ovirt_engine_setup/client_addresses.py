#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
#


"""The addresses engine-setup always keeps on the terminal IP list.

The list (``Require ip`` in z-ovirt-engine-proxy.conf) turns away every address not on it. Two of
them must never be missing, whatever the operator typed in: the loopback address, through which
the engine's own components reach the web server, and the address of the engine host itself, from
which it is installed, administered and checked. Both are put first on the list at every
engine-setup.
"""


import ipaddress
import socket


LOOPBACK_ADDRESS = '127.0.0.1'
# 'localhost' resolves to ::1 first on Rocky Linux 9 (/etc/hosts), so a client on the engine host
# itself - the hosted-engine deployment checking the health page, a curl - comes in over IPv6.
IPV6_LOOPBACK_ADDRESS = '::1'
LOOPBACK_ADDRESSES = (LOOPBACK_ADDRESS, IPV6_LOOPBACK_ADDRESS)

# A documentation address (RFC 5737): connecting a UDP socket to it sends nothing, it only makes
# the kernel choose the source address of the default route.
_ROUTE_PROBE = ('203.0.113.1', 9)


def _is_host_address(address):
    """Whether the address is one of this host's own (it can be bound to)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((address, 0))
        return True
    except OSError:
        return False


def _default_route_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(_ROUTE_PROBE)
            return probe.getsockname()[0]
    except OSError:
        return None


def _resolve(fqdn):
    if not fqdn:
        return []
    try:
        return [
            info[4][0]
            for info in socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
        ]
    except (OSError, UnicodeError):
        return []


def engine_host_addresses(fqdn, resolve=_resolve, default_route=_default_route_address,
                          is_host_address=_is_host_address):
    """The IPv4 addresses of the engine host: those its FQDN resolves to that this host has, and
    the source address of its default route. Loopback and unspecified addresses are left out.
    """
    addresses = []
    for candidate in list(resolve(fqdn)) + [default_route()]:
        if not candidate:
            continue
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            continue
        text = str(address)
        if text not in addresses and is_host_address(text):
            addresses.append(text)
    return addresses


def with_required_addresses(allowed, host_addresses):
    """The list with the loopback addresses (IPv4 and IPv6) and the engine host's addresses
    first, each once."""
    required = list(LOOPBACK_ADDRESSES) + list(host_addresses)
    result = []
    for address in required + list(allowed or ()):
        if address and address not in result:
            result.append(address)
    return result


# vim: expandtab tabstop=4 shiftwidth=4
