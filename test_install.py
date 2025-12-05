import unittest
from unittest.mock import patch, MagicMock
import sys
import subprocess
import runpy

class TestServerInstall(unittest.TestCase):

    @patch('subprocess.run')
    @patch('sys.argv', ['server.py'])
    @patch('mcp.server.fastmcp.FastMCP.run')
    def test_install_execution(self, mock_mcp_run, mock_run):
        # Mock subprocess.run
        mock_run.return_value.stdout = "Installed"
        
        # Run the server module
        runpy.run_path('server.py', run_name='__main__')
        
        # Verify uv pip install was called
        mock_run.assert_any_call(
            ["uv", "pip", "install", "catocli"],
            check=True,
            capture_output=True
        )
        
        # Verify mcp.run was called
        mock_mcp_run.assert_called_once()

if __name__ == '__main__':
    unittest.main()
