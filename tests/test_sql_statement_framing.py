"""SQL shim regressions using the actual framed backend protocol and SQLite."""

import unittest

from tests.test_backend_state_protocol import ShimProcess


class SqlStatementFramingTests(unittest.TestCase):
    def setUp(self):
        self.shim = ShimProcess("sql_shim.py")

    def tearDown(self):
        self.shim.close()

    def execute(self, code):
        return self.shim.request({"cmd": "exec", "code": code, "bindings": {}})

    def test_semicolons_quotes_and_comments_preserve_query_values(self):
        result = self.execute(
            "-- comment with ; and ' characters\n"
            "SELECT 'semi;colon ''quoted''' AS value; /* another ; */"
        )
        self.assertEqual("ok", result["status"])
        self.assertEqual({"t": "str", "v": "semi;colon 'quoted'"}, result["value"])

    def test_multi_statement_trigger_executes_as_one_sqlite_statement(self):
        result = self.execute(
            "CREATE TABLE items(value INTEGER);"
            "CREATE TABLE audit(value INTEGER);"
            "CREATE TRIGGER item_log AFTER INSERT ON items BEGIN "
            "INSERT INTO audit VALUES(new.value);"
            "INSERT INTO audit VALUES(new.value + 1); END;"
            "INSERT INTO items VALUES(4);"
            "SELECT SUM(value) AS total FROM audit;"
        )
        self.assertEqual("ok", result["status"])
        self.assertEqual({"t": "int", "v": 9}, result["value"])
        checkpoint = self.shim.request({"cmd": "checkpoint_v1", "max_bytes": 1048576})
        self.assertEqual("state_pin_required_v1", checkpoint["status"])

    def test_last_query_and_returning_use_actual_cursor_results(self):
        result = self.execute("SELECT 1; SELECT 2 AS last_value")
        self.assertEqual({"t": "int", "v": 2}, result["value"])
        result = self.execute(
            "CREATE TABLE items(value); INSERT INTO items VALUES (42) RETURNING value;"
        )
        self.assertEqual({"t": "int", "v": 42}, result["value"])

    def test_malformed_quote_fails_and_next_request_is_independent(self):
        result = self.execute("SELECT 'unterminated;")
        self.assertEqual("err", result["status"])
        self.assertIn("sqlite3.OperationalError", result["message"])
        result = self.execute("SELECT 42 AS value;")
        self.assertEqual("ok", result["status"])
        self.assertEqual({"t": "int", "v": 42}, result["value"])

    def test_old_native_marker_is_ordinary_sql_data(self):
        result = self.execute("SELECT '__O_SQL_DONE__' AS value;")
        self.assertEqual({"t": "str", "v": "__O_SQL_DONE__"}, result["value"])


if __name__ == "__main__":
    unittest.main()
