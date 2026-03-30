#!/usr/bin/env python3
"""
Test script to find correct PDF coordinates for EXECUTION table.
Draws test markers at various Y positions to identify correct placement.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, IndemnityRequest, KYCCustomer, IndemnityTemplate, UPLOAD_FOLDER
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from io import BytesIO
from werkzeug.utils import secure_filename


def test_coordinates(indemnity_request, customer):
    """Test various Y coordinates to find correct position for EXECUTION table."""
    
    template = IndemnityTemplate.query.filter_by(id=indemnity_request.template_id).first()
    if not template or not template.pdf_path:
        print("No template found")
        return None
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pdf_path = os.path.join(base_dir, template.pdf_path) if not template.pdf_path.startswith('/') else template.pdf_path
    
    if not os.path.exists(pdf_path):
        print(f"PDF not found: {pdf_path}")
        return None
    
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        
        first_page = reader.pages[0]
        page_width = float(first_page.mediabox.width)
        page_height = float(first_page.mediabox.height)
        
        print(f"Page dimensions: width={page_width}, height={page_height}")
        print(f"Testing Y coordinates from 50 to 800...")
        
        for page_num, page in enumerate(reader.pages):
            packet = BytesIO()
            c = canvas.Canvas(packet, pagesize=(page_width, page_height))
            
            if page_num == len(reader.pages) - 1:
                c.setFont("Helvetica-Bold", 8)
                c.setFillColorRGB(1, 0, 0)  # Red color for visibility
                
                # Draw test markers at various Y positions
                test_ys = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800]
                
                for y in test_ys:
                    if y < page_height:
                        c.drawString(50, y, f"Y={y}")
                        c.line(50, y, 200, y)  # Draw line at this Y position
                
                # Also draw test boxes where EXECUTION table should be
                c.setFillColorRGB(0, 1, 0)  # Green for expected positions
                c.drawString(100, 400, "TEST: Full Name (y=400)")
                c.drawString(295, 400, "TEST: Date (y=400)")
                c.drawString(480, 400, "TEST: Place (y=400)")
                
                c.setFillColorRGB(0, 0, 1)  # Blue for signature
                c.drawString(130, 320, "TEST: Signature (y=320)")
            
            c.save()
            packet.seek(0)
            
            from PyPDF2 import PdfReader as OverlayReader
            overlay = OverlayReader(packet)
            if len(overlay.pages) > 0:
                page.merge_page(overlay.pages[0])
            
            writer.add_page(page)
        
        # Save test PDF
        test_filename = f"test_coordinates_{secure_filename(customer.name.replace(' ', '_'))}.pdf"
        signed_dir = os.path.join(UPLOAD_FOLDER, 'signed')
        os.makedirs(signed_dir, exist_ok=True)
        test_path = os.path.join(signed_dir, test_filename)
        
        with open(test_path, 'wb') as output_file:
            writer.write(output_file)
        
        test_relative_path = os.path.join('uploads', 'kyc', 'signed', test_filename)
        print(f"\nTest PDF created: {test_relative_path}")
        print(f"Open this PDF to see where Y coordinates land on the page")
        print(f"URL: http://127.0.0.1:5000/uploads/{test_relative_path}")
        return test_relative_path
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Main function to create coordinate test PDF."""
    
    with app.app_context():
        print("=" * 60)
        print("CREATING COORDINATE TEST PDF")
        print("=" * 60)
        print()
        
        # Find first signed request to use as template
        signed_request = IndemnityRequest.query.filter(
            IndemnityRequest.signature_data.isnot(None)
        ).first()
        
        if not signed_request:
            print("No signed indemnity requests found")
            return
        
        customer = KYCCustomer.query.get(signed_request.customer_id)
        if not customer:
            print("Customer not found")
            return
        
        print(f"Creating test PDF for: {customer.name}")
        result = test_coordinates(signed_request, customer)
        
        if result:
            print()
            print("Test PDF created successfully!")
            print("Open the PDF to see red markers at various Y positions")
            print("This will help identify correct coordinates for EXECUTION table")


if __name__ == '__main__':
    main()
