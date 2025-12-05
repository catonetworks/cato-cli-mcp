import unittest
from unittest.mock import patch, MagicMock
import sys
import subprocess
import runpy
from io import StringIO

class TestConfigError(unittest.TestCase):

    @patch('subprocess.run')
    @patch('sys.argv', ['server.py', '--account-id', '123', '--cato-token', 'abc'])
    def test_config_error_logging(self, mock_run):
        # Mock subprocess.run to raise CalledProcessError
        error = subprocess.CalledProcessError(1, ['cmd'])
        error.stdout = b"Output message"
        error.stderr = b"Error message"
        mock_run.side_effect = error
        
        # Capture stderr
        captured_stderr = StringIO()
        sys.stderr = captured_stderr
        
        try:
            # Run the server module
            with self.assertRaises(SystemExit):
                runpy.run_path('server.py', run_name='__main__')
        finally:
            # Restore stderr
            sys.stderr = sys.__stderr__
            
        output = captured_stderr.getvalue()
        self.assertIn("Stdout: Output message", output)
        self.assertIn("Stderr: Error message", output)

if __name__ == '__main__':
    unittest.main()
