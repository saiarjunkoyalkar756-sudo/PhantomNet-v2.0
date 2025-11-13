import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path to allow for package-like imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from backend_api.report_service import ReportService

class TestReportService(unittest.TestCase):

    def setUp(self):
        self.report_service = ReportService()
        self.threat_data = {
            "threat_id": "T12345",
            "threat_type": "Malware Infection",
            "source_ip": "192.168.1.100",
            "severity": "Critical",
            "status": "Active"
        }
        self.expected_content_part = "Threat Details:\n- Threat Id: T12345\n- Threat Type: Malware Infection\n- Source Ip: 192.168.1.100\n- Severity: Critical\n- Status: Active"

    def test_generate_threat_report_content(self):
        print("\n--- Testing generate_threat_report_content ---")
        content = self.report_service.generate_threat_report_content(self.threat_data)
        print(f"Generated content (partial): \n{content[:200]}...") # Print first 200 chars
        self.assertIn("PhantomNet Threat Report", content)
        self.assertIn(self.expected_content_part, content)
        self.assertIn("Analysis Summary:", content)

    @patch('backend_api.report_service.FPDF')
    def test_export_to_pdf(self, mock_fpdf):
        print("\n--- Testing export_to_pdf ---")
        mock_pdf_instance = MagicMock()
        mock_fpdf.return_value = mock_pdf_instance

        content = self.report_service.generate_threat_report_content(self.threat_data)
        filename = "test_threat_report.pdf"
        
        exported_filename = self.report_service.export_to_pdf(content, filename)
        
        mock_fpdf.assert_called_once()
        mock_pdf_instance.add_page.assert_called_once()
        mock_pdf_instance.set_font.assert_called_once_with("Arial", size=12)
        mock_pdf_instance.output.assert_called_once_with(filename)
        self.assertEqual(exported_filename, filename)
        print(f"PDF export mocked successfully for {filename}")

if __name__ == "__main__":
    unittest.main()
