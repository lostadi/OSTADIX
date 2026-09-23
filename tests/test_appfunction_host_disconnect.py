"""Caller loss and host deadlines cancel once, with distinct response rules."""
import importlib.util
import io
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'ostadix_appfunction_host.py'
SPEC = importlib.util.spec_from_file_location('appfunction_host_disconnect', SCRIPT)
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class HostDisconnectTests(unittest.TestCase):
    def exchange(self, receive, settling=False, timeout=False, deadline=False, result=None):
        handler = HOST.Handler.__new__(HOST.Handler)
        body = json.dumps({'source': '2', 'constraints': {'timeout_ms': 1000}}).encode()
        handler.path = '/o_execute'
        handler.headers = {'Authorization': 'Bearer synthetic-token', 'Content-Length': str(len(body))}
        handler.rfile = io.BytesIO(body)
        handler.connection = Mock()
        if isinstance(receive, (Exception, list)):
            handler.connection.recv.side_effect = receive
        else:
            handler.connection.recv.return_value = receive
        handler.respond = Mock()
        handler.server = SimpleNamespace(
            config={'token': 'synthetic-token', 'max_timeout_ms': 900000,
                    'root': '/unused', 'mcp_executable': '/unused/mcp'},
            slots=HOST.threading.BoundedSemaphore(1))
        if result is None:
            result = {'isError': True, 'structuredContent': {'state': 'cancelled'}}
        frames = Mock()
        frames.get.side_effect = ([{'id': 1, 'result': {}}, None]
                                  + ([None] if settling or timeout else [])
                                  + [{'id': 2, 'result': result}])
        if deadline:
            clock = Mock(side_effect=[100, 107, 107, 113 if timeout else 107])
        else:
            clock = Mock(side_effect=[100, 100, 106]) if timeout else Mock(return_value=100)
        with patch.object(HOST.subprocess, 'Popen') as popen, \
                patch.object(HOST.queue, 'Queue', return_value=frames), \
                patch.object(HOST.threading, 'Thread'), \
                patch.object(HOST.time, 'monotonic', clock), \
                patch.object(HOST.select, 'select', return_value=([handler.connection], [], [])), \
                patch.object(HOST, 'send') as send, patch.object(HOST, 'log') as log:
            handler.do_POST()
            popen.assert_called_once()
            messages = [call.args[1] for call in send.call_args_list]
            events = [call.args[0] for call in log.call_args_list]
        self.assertEqual(sum(message.get('method') == 'tools/call' for message in messages), 1)
        if not timeout:
            self.assertNotIn('host_failure', events)
        self.assertTrue(handler.server.slots.acquire(blocking=False))
        return handler, messages, events

    def test_reset_tls_eof_and_clean_close_cancel_once_without_response_or_retry(self):
        for receive in [ConnectionResetError('peer reset'), BrokenPipeError('peer closed'),
                        ssl.SSLEOFError('unexpected EOF'), b'']:
            with self.subTest(receive=repr(receive)):
                handler, messages, events = self.exchange(receive)
                cancellations = [message for message in messages
                                 if message.get('method') == 'notifications/cancelled']
                self.assertEqual(len(cancellations), 1)
                self.assertEqual(cancellations[0]['params']['requestId'], 2)
                self.assertEqual(events.count('mcp_cancel'), 1)
                handler.respond.assert_not_called()

    def test_cancelled_socket_is_not_read_again_while_mcp_settles(self):
        handler, messages, events = self.exchange(
            [ConnectionResetError('peer reset'), BrokenPipeError('read after reset')],
            settling=True)
        handler.connection.recv.assert_called_once_with(1)
        self.assertEqual(events.count('mcp_cancel'), 1)
        self.assertIn('mcp_result', events)
        handler.respond.assert_not_called()

    def test_cancelled_request_retains_bounded_settlement_deadline(self):
        handler, messages, events = self.exchange(ConnectionResetError('peer reset'), timeout=True)
        handler.connection.recv.assert_called_once_with(1)
        self.assertEqual(events.count('mcp_cancel'), 1)
        self.assertEqual(events.count('host_failure'), 1)
        self.assertNotIn('mcp_result', events)
        handler.respond.assert_not_called()

    def test_connected_deadline_returns_real_timed_out_result_without_retry(self):
        result = {'isError': True, 'structuredContent': {
            'state': 'timed_out', 'error': 'timeout after 1s',
            'cleanup': {'child_reaped': True, 'logs_drained': True}}}
        handler, messages, events = self.exchange(
            [ssl.SSLWantReadError(), BrokenPipeError('unnecessary read after cancellation')],
            deadline=True, settling=True, result=result)
        handler.connection.recv.assert_called_once_with(1)
        self.assertEqual(events.count('mcp_cancel'), 1)
        self.assertIn('mcp_result', events)
        handler.respond.assert_called_once_with(200, result)
        self.assertIs(handler.respond.call_args.args[1], result)

    def test_connected_deadline_settlement_timeout_returns_bounded_failure(self):
        handler, messages, events = self.exchange(ssl.SSLWantReadError(), deadline=True, timeout=True)
        handler.connection.recv.assert_called_once_with(1)
        self.assertEqual(events.count('mcp_cancel'), 1)
        self.assertEqual(events.count('host_failure'), 1)
        self.assertNotIn('mcp_result', events)
        status, response = handler.respond.call_args.args
        self.assertEqual(status, 502)
        self.assertEqual(response['error'], 'MCP did not settle cancellation; no retry')
        self.assertIs(response['retry'], False)

    def test_pending_tls_read_does_not_cancel_a_connected_caller(self):
        for receive in [ssl.SSLWantReadError(), BlockingIOError()]:
            with self.subTest(receive=repr(receive)):
                handler, messages, events = self.exchange(receive)
                self.assertFalse(any(message.get('method') == 'notifications/cancelled'
                                     for message in messages))
                self.assertNotIn('mcp_cancel', events)
                handler.respond.assert_called_once()
                self.assertEqual(handler.respond.call_args.args[0], 200)


if __name__ == '__main__':
    unittest.main()
