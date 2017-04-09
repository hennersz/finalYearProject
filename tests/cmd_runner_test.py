#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.clients.cmd_runner import CMDRunnerFactory
from twisted.test import proto_helpers
import pytest


@pytest.fixture
def protocol():
    factory = CMDRunnerFactory(['cmd1', 'cmd2', 'cmd3'])
    proto = factory.buildProtocol(None)
    return proto


@pytest.fixture
def transport(protocol):
    tr = proto_helpers.StringTransport()
    protocol.makeConnection(tr)
    return tr


def test_runner(protocol, transport):
    protocol.dataReceived('connected')
    assert transport.value() == 'cmd1'
    transport.clear()

    protocol.dataReceived('more')
    assert transport.value() == 'cmd2'
    transport.clear()

    protocol.dataReceived('more')
    assert transport.value() == 'cmd3'
    transport.clear()

    protocol.dataReceived('more')
    assert transport.disconnecting
