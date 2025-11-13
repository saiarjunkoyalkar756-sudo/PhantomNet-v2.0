from fpdf import FPDF
import datetime

class ReportService:
    """
    Service for generating and exporting reports, including PDF format.
    """
    def __init__(self):
        print("Initializing Report Service...")

    def generate_threat_report_content(self, threat_data: dict):
        """
        Generates textual content for a threat report.
        """
        report_title = "PhantomNet Threat Report"
        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        content = [
            f"{report_title}\n",
            f"Date: {report_date}\n",
            "--------------------------------------------------\n",
            "Threat Details:\n"
        ]
        
        for key, value in threat_data.items():
            content.append(f"- {key.replace('_', ' ').title()}: {value}\n")
            
        content.append("\n--------------------------------------------------\n")
        content.append("Analysis Summary: This report details a detected threat within the PhantomNet ecosystem. Further actions may be recommended based on the threat level and type.")
        
        return "".join(content)

    def export_to_pdf(self, content: str, filename: str = "threat_report.pdf"):
        """
        Exports the given content to a PDF file.
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Add content line by line
        for line in content.split('\n'):
            pdf.multi_cell(0, 10, line)
            
        pdf.output(filename)
        print(f"Report exported to {filename}")
        return filename
