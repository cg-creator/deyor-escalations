#!/usr/bin/env python3
"""
Script to reprocess existing signed KYC PDFs with corrected coordinates.
This fixes previously signed PDFs where name, date, place, and signature 
were appearing at the bottom instead of in the proper form fields.

Usage: python reprocess_signed_pdfs.py
"""

import os
import sys

# Add parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, IndemnityRequest, KYCCustomer, IndemnityTemplate, UPLOAD_FOLDER, find_pdf_fields
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from io import BytesIO
from werkzeug.utils import secure_filename
import json


def reprocess_signed_pdf(indemnity_request, customer):
    """Reprocess a single signed PDF with corrected coordinates."""
    
    # Get signature data from the existing record
    signature_data_str = indemnity_request.signature_data or ""
    signature_image_path = None
    signed_pdf_path = None
    
    # Extract image path and existing PDF path from signature_data
    if signature_data_str:
        parts = signature_data_str.split('|')
        for part in parts:
            if part.startswith('img:'):
                signature_image_path = part.replace('img:', '')
            elif part.startswith('pdf:'):
                signed_pdf_path = part.replace('pdf:', '')
    
    if not signature_image_path:
        print(f"  [skip] No signature image found for customer {customer.name}")
        return None
    
    # Get template PDF
    template = IndemnityTemplate.query.filter_by(id=indemnity_request.template_id).first()
    if not template or not template.pdf_path:
        print(f"  [skip] No template found for customer {customer.name}")
        return None
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Get source PDF (use template or existing processed PDF)
    pdf_path = os.path.join(base_dir, template.pdf_path) if not template.pdf_path.startswith('/') else template.pdf_path
    
    if not os.path.exists(pdf_path):
        print(f"  [skip] PDF not found: {pdf_path}")
        return None
    
    # Parse location
    location = ""
    if indemnity_request.terms_accepted_location:
        location = indemnity_request.terms_accepted_location
    elif signature_data_str:
        for part in signature_data_str.split('|'):
            if part.startswith('loc:'):
                location = part.replace('loc:', '')
                break
    
    # Get full name
    full_name = customer.name
    if customer.submission and customer.submission.form_data:
        try:
            form_data = json.loads(customer.submission.form_data)
            if form_data.get('full_name'):
                full_name = form_data['full_name']
        except:
            pass
    
    # Format date
    signed_date = ""
    if indemnity_request.signed_at:
        signed_date = indemnity_request.signed_at.strftime('%d/%m/%Y')
    
    try:
        # Read the PDF
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        
        # Get page size
        first_page = reader.pages[0]
        page_width = float(first_page.mediabox.width)
        page_height = float(first_page.mediabox.height)
        
        # Get field positions dynamically
        field_positions = find_pdf_fields(pdf_path)
        
        # Process each page
        for page_num, page in enumerate(reader.pages):
            packet = BytesIO()
            c = canvas.Canvas(packet, pagesize=(page_width, page_height))
            
            # Add signature and execution details on the last page
            if page_num == len(reader.pages) - 1:
                try:
                    # ===== EXECUTION TABLE FIELDS =====
                    c.setFont("Helvetica-Bold", 10)
                    c.setFillColorRGB(0, 0, 0)
                    
                    # Use dynamically detected positions or fallback to correct coordinates
                    if field_positions and 'full_name' in field_positions:
                        x, y = field_positions['full_name']
                        c.drawString(x, y, full_name)
                    else:
                        # Fallback: Full Name box is at x=56.7-226.9, y=309.2-327.9
                        c.drawString(62, 312, full_name)
                    
                    if field_positions and 'date' in field_positions:
                        x, y = field_positions['date']
                        c.drawString(x, y, signed_date)
                    else:
                        # Fallback: Date box is at x=226.9-376.9, y=309.2-327.9  
                        c.drawString(232, 312, signed_date)
                    
                    if field_positions and 'place' in field_positions:
                        x, y = field_positions['place']
                        c.drawString(x, y, location)
                    else:
                        # Fallback: Place box is at x=376.9-538.9, y=309.2-327.9
                        c.drawString(382, 312, location)
                    
                    # ===== SIGNATURE OF PARTICIPANT BOX =====
                    full_sig_path = os.path.join(base_dir, signature_image_path) if not signature_image_path.startswith('/') else signature_image_path
                    
                    if signature_image_path.startswith('typed:'):
                        sig_text = signature_image_path.replace('typed:', '')
                        c.setFont("Times-Italic", 18)
                        c.setFillColorRGB(0, 0, 0.8)
                        if field_positions and 'signature' in field_positions:
                            x, y = field_positions['signature']
                            c.drawString(x, y, sig_text)
                        else:
                            c.drawString(130, 320, sig_text)
                    elif os.path.exists(full_sig_path):
                        img = ImageReader(full_sig_path)
                        if field_positions and 'signature' in field_positions:
                            x, y = field_positions['signature']
                            c.drawImage(img, x, y - 30, width=200, height=50, mask='auto')
                        else:
                            c.drawImage(img, 130, 300, width=200, height=50, mask='auto')
                    
                    # Add timestamp below signature box
                    c.setFont("Helvetica", 7)
                    c.setFillColorRGB(0.4, 0.4, 0.4)
                    from datetime import timedelta
                    if indemnity_request.signed_at:
                        ist_offset = timedelta(hours=5, minutes=30)
                        ist_time = (indemnity_request.signed_at + ist_offset).strftime('%d-%m-%Y %I:%M %p')
                    else:
                        ist_time = ''
                    c.drawString(130, 285, f"Signed: {ist_time} IST | IP: {indemnity_request.ip_address or 'N/A'}")
                    
                except Exception as sig_e:
                    print(f"  [warn] Failed to embed signature elements: {sig_e}")
            
            c.save()
            packet.seek(0)
            
            # Merge overlay with page
            try:
                from PyPDF2 import PdfReader as OverlayReader
                overlay = OverlayReader(packet)
                if len(overlay.pages) > 0:
                    page.merge_page(overlay.pages[0])
            except Exception as e:
                print(f"  [warn] Could not merge overlay for page {page_num}: {e}")
            
            writer.add_page(page)
        
        # Create new signed PDF filename
        signed_filename = f"signed_{secure_filename(customer.name.replace(' ', '_'))}_{indemnity_request.id}.pdf"
        signed_dir = os.path.join(UPLOAD_FOLDER, 'signed')
        os.makedirs(signed_dir, exist_ok=True)
        signed_path = os.path.join(signed_dir, signed_filename)
        
        # Write the signed PDF
        with open(signed_path, 'wb') as output_file:
            writer.write(output_file)
        
        # Return relative path
        signed_relative_path = os.path.join('uploads', 'kyc', 'signed', signed_filename)
        
        # Update the indemnity request with new PDF path
        indemnity_request.signature_data = f"{signature_data_str.split('|pdf:')[0]}|pdf:{signed_relative_path}"
        
        print(f"  [success] Reprocessed: {signed_relative_path}")
        return signed_relative_path
        
    except Exception as e:
        print(f"  [error] Failed to reprocess PDF for {customer.name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Main function to reprocess all signed PDFs."""
    
    with app.app_context():
        print("=" * 60)
        print("REPROCESSING SIGNED KYC PDFs")
        print("=" * 60)
        print()
        
        # Get all indemnity requests that have been signed
        signed_requests = IndemnityRequest.query.filter(
            IndemnityRequest.signature_data.isnot(None)
        ).all()
        
        print(f"Found {len(signed_requests)} signed indemnity requests to reprocess")
        print()
        
        success_count = 0
        skip_count = 0
        error_count = 0
        
        for i, indemnity_request in enumerate(signed_requests, 1):
            customer = KYCCustomer.query.get(indemnity_request.customer_id)
            if not customer:
                print(f"[{i}/{len(signed_requests)}] Customer not found for request {indemnity_request.id}")
                skip_count += 1
                continue
            
            print(f"[{i}/{len(signed_requests)}] Processing: {customer.name}")
            
            result = reprocess_signed_pdf(indemnity_request, customer)
            
            if result:
                success_count += 1
            else:
                skip_count += 1
            
            # Commit after each successful reprocess
            if result:
                db.session.commit()
        
        print()
        print("=" * 60)
        print("REPROCESSING COMPLETE")
        print("=" * 60)
        print(f"Success: {success_count}")
        print(f"Skipped: {skip_count}")
        print(f"Errors: {error_count}")
        print()
        print("All previously signed PDFs have been reprocessed with corrected coordinates.")
        print("The name, date, place, and signature should now appear in the proper form fields.")


if __name__ == '__main__':
    main()
