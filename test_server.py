import unittest
from unittest.mock import patch, MagicMock
import server

class TestCatoServer(unittest.TestCase):

    @patch('server.subprocess.run')
    def test_cato_entity(self, mock_run):
        mock_run.return_value.stdout = "Entity lookup result"
        result = server.cato_entity("lookup", ["--id", "123"])
        
        mock_run.assert_called_with(
            ["catocli", "entity", "lookup", "--id", "123"],
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result, "Entity lookup result")

    @patch('server.subprocess.run')
    def test_cato_query(self, mock_run):
        mock_run.return_value.stdout = "Query result"
        result = server.cato_query("accountSnapshot", ["--id", "123"])
        
        mock_run.assert_called_with(
            ["catocli", "query", "accountSnapshot", "--id", "123"],
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result, "Query result")

    @patch('server.subprocess.run')
    def test_cato_mutation(self, mock_run):
        mock_run.return_value.stdout = "Mutation result"
        result = server.cato_mutation("site", ["--name", "NewSite"])
        
        mock_run.assert_called_with(
            ["catocli", "mutation", "site", "--name", "NewSite"],
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result, "Mutation result")

    @patch('server.subprocess.run')
    def test_cato_raw(self, mock_run):
        mock_run.return_value.stdout = "GraphQL result"
        query = "{ me { id } }"
        result = server.cato_raw(query)
        
        mock_run.assert_called_with(
            ["catocli", "raw", query],
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result, "GraphQL result")

if __name__ == '__main__':
    unittest.main()
