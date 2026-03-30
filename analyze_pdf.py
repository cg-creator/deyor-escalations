#!/usr/bin/env python3
"""
Test script to analyze PDF structure and find field positions dynamically.
"""

import pdfplumber
import os

pdf_path = "/Users/chirag/Deyor Escalation/uploads/kyc/indemnity_GY-fivVPniet0--0eyoYGA.pdf"

with pdfplumber.open(pdf_path) as pdf:
    print(f"Total pages: {len(pdf.pages)}")
    
    # Analyze last page (where form fields are)
    last_page = pdf.pages[-1]
    print(f"\nLast page dimensions: {last_page.width} x {last_page.height}")
    
    # Extract text with positions
    words = last_page.extract_words()
    print(f"\nFound {len(words)} words on last page")
    
    # Look for keywords
    keywords = ['Full Name', 'Date', 'Place', 'Signature', 'EXECUTION', 'PARTICIPANT']
    print("\n=== KEYWORD POSITIONS ===")
    for word in words:
        text = word['text']
        for kw in keywords:
            if kw.lower() in text.lower():
                print(f"'{text}' at x={word['x0']:.1f}, y={word['top']:.1f} (bottom={word['bottom']:.1f})")
                break
    
    # Look for lines/underscores
    print("\n=== ALL TEXT ELEMENTS (sorted by Y position) ===")
    sorted_words = sorted(words, key=lambda w: w['top'])
    for word in sorted_words[-30:]:  # Show last 30 elements (bottom of page)
        print(f"'{word['text']}' at y={word['top']:.1f}-{word['bottom']:.1f}, x={word['x0']:.1f}-{word['x1']:.1f}")
