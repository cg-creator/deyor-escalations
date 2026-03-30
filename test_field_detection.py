#!/usr/bin/env python3
"""Test the dynamic field detection."""

import sys
sys.path.insert(0, '/Users/chirag/Deyor Escalation')

from app import find_pdf_fields

pdf_path = "/Users/chirag/Deyor Escalation/uploads/kyc/indemnity_GY-fivVPniet0--0eyoYGA.pdf"

print("Testing dynamic field detection...")
positions = find_pdf_fields(pdf_path)

if positions:
    print(f"\nDetected positions: {positions}")
    print("\nField positions found:")
    for field, (x, y) in positions.items():
        print(f"  {field}: x={x}, y={y}")
else:
    print("Failed to detect positions - will use fallback")
