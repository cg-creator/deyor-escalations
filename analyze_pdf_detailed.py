#!/usr/bin/env python3
"""
Analyze PDF to find exact positions of blank lines for Name, Date, Place, Signature.
Uses pdfplumber to detect text and line elements.
"""

import pdfplumber
import os

pdf_path = "/Users/chirag/Deyor Escalation/uploads/kyc/indemnity_GY-fivVPniet0--0eyoYGA.pdf"

with pdfplumber.open(pdf_path) as pdf:
    last_page = pdf.pages[-1]
    
    # Get page dimensions
    print(f"Page size: {last_page.width} x {last_page.height}")
    print()
    
    # Extract words with positions
    words = last_page.extract_words()
    
    # Find relevant labels and their positions
    labels_found = {}
    for word in words:
        text = word['text']
        if 'Full' in text or 'Name' in text:
            labels_found['Name'] = word
        elif text == 'Date':
            labels_found['Date'] = word
        elif text == 'Place':
            labels_found['Place'] = word
        elif 'Signature' in text:
            labels_found['Signature'] = word
        elif 'EXECUTION' in text:
            labels_found['EXECUTION'] = word
    
    print("=== LABELS FOUND ===")
    for label, pos in labels_found.items():
        print(f"{label}: x={pos['x0']:.1f}, y={pos['top']:.1f} (bottom={pos['bottom']:.1f})")
    
    # Look for lines/rectangles (the blank lines)
    print("\n=== DRAWING ELEMENTS (potential blank lines) ===")
    try:
        lines = last_page.lines
        for i, line in enumerate(lines[-10:]):  # Last 10 lines
            print(f"Line {i}: x={line['x0']:.1f}-{line['x1']:.1f}, y={line['top']:.1f}-{line['bottom']:.1f}")
    except:
        print("No lines found")
    
    # Look for rectangles
    try:
        rects = last_page.rects
        for i, rect in enumerate(rects[-10:]):
            print(f"Rect {i}: x={rect['x0']:.1f}-{rect['x1']:.1f}, y={rect['top']:.1f}-{rect['bottom']:.1f}")
    except:
        print("No rects found")
    
    # Extract all text by Y position (bottom-up)
    print("\n=== TEXT ELEMENTS BY Y POSITION (bottom 20) ===")
    sorted_words = sorted(words, key=lambda w: w['top'], reverse=True)
    for word in sorted_words[:20]:
        print(f"y={word['top']:.1f}: '{word['text']}' (x={word['x0']:.1f}-{word['x1']:.1f})")
