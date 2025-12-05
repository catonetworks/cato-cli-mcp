import unittest
from unittest.mock import patch, MagicMock
import sys
import subprocess
import runpy

class TestServerConfig(unittest.TestCase):

    @patch('subprocess.run')
    @patch('sys.argv', ['server.py', '--account-id', '123', '--cato-token', 'abc'])
    @patch('mcp.server.fastmcp.FastMCP.run')
    def test_config_execution(self, mock_mcp_run, mock_run):
        # Mock subprocess.run to avoid actual execution
        mock_run.return_value.stdout = "Configured"
        
        # Run the server module
        runpy.run_path('server.py', run_name='__main__')
        
        # Verify catocli configure was called
        mock_run.assert_any_call(
            ["catocli", "configure", "set", "--cato-token", "abc", "--account-id", "123"],
            check=True,
            capture_output=True
        )
        
        # Verify mcp.run was called
        mock_mcp_run.assert_called_once()

    @patch('subprocess.run')
    @patch('sys.argv', ['server.py'])
    @patch('mcp.server.fastmcp.FastMCP.run')
    def test_no_config_execution(self, mock_mcp_run, mock_run):
        # Run the server module without args
        runpy.run_path('server.py', run_name='__main__')
        
        # Verify catocli configure was NOT called with these args
        # Note: subprocess.run might be called by other things, so we check specifically for configure
        for call in mock_run.call_args_list:
            args, _ = call
            if args[0] and "configure" in args[0]:
                 self.fail("configure should not be called without args")
        
        # Verify mcp.run was called
        mock_mcp_run.assert_called_once()

if __name__ == '__main__':
    unittest.main()
