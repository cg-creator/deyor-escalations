#!/usr/bin/env python3
"""
Comprehensive PDF field detection using pdfplumber.
Finds labels and their associated input boxes/blank lines.
"""

import pdfplumber
import os

pdf_path = "/Users/chirag/Deyor Escalation/uploads/kyc/indemnity_GY-fivVPniet0--0eyoYGA.pdf"

with pdfplumber.open(pdf_path) as pdf:
    last_page = pdf.pages[-1]
    
    print(f"Page size: {last_page.width} x {last_page.height}")
    print()
    
    # Extract words with positions
    words = last_page.extract_words()
    
    # Find label positions
    labels = {}
    for i, word in enumerate(words):
        text = word['text']
        text_lower = text.lower()
        
        if text_lower == 'full' and i + 1 < len(words):
            next_word = words[i + 1]
            if next_word['text'].lower() == 'name':
                labels['full_name'] = {
                    'x': word['x0'],
                    'y': word['top'],
                    'width': next_word['x1'] - word['x0'],
                    'height': word['bottom'] - word['top']
                }
        elif text_lower == 'date':
            labels['date'] = {
                'x': word['x0'],
                'y': word['top'],
                'width': word['x1'] - word['x0'],
                'height': word['bottom'] - word['top']
            }
        elif text_lower == 'place':
            labels['place'] = {
                'x': word['x0'],
                'y': word['top'],
                'width': word['x1'] - word['x0'],
                'height': word['bottom'] - word['top']
            }
        elif 'signature' in text_lower and ':' in text:
            labels['signature'] = {
                'x': word['x0'],
                'y': word['top'],
                'width': word['x1'] - word['x0'],
                'height': word['bottom'] - word['top']
            }
    
    print("=== LABELS FOUND ===")
    for name, pos in labels.items():
        print(f"{name}: x={pos['x']:.1f}, y={pos['y']:.1f}")
    
    # Find rectangles (the blank boxes)
    print("\n=== RECTANGLES (Blank Boxes) ===")
    try:
        rects = last_page.rects
        # Filter for likely form field boxes
        form_boxes = []
        for rect in rects:
            width = rect['x1'] - rect['x0']
            height = rect['bottom'] - rect['top']
            # Form fields are typically wide and short
            if width > 50 and height < 30:
                form_boxes.append(rect)
                print(f"Box: x={rect['x0']:.1f}-{rect['x1']:.1f}, y={rect['top']:.1f}-{rect['bottom']:.1f} (w={width:.1f}, h={height:.1f})")
        
        print(f"\nFound {len(form_boxes)} potential form boxes")
        
        # Match boxes to labels by x-position
        print("\n=== MATCHING BOXES TO LABELS ===")
        field_positions = {}
        
        for label_name, label_pos in labels.items():
            label_x = label_pos['x'] + (label_pos['width'] / 2)  # Center of label
            label_y = label_pos['y']
            
            # Find closest box that overlaps or is near this label
            closest_box = None
            min_distance = float('inf')
            
            for box in form_boxes:
                box_x = (box['x0'] + box['x1']) / 2  # Center of box
                box_center_y = (box['top'] + box['bottom']) / 2  # Center of box
                
                # Box should be roughly aligned horizontally with label
                x_diff = abs(box_x - label_x)
                # Box can overlap with label or be nearby
                y_diff = abs(box_center_y - label_y)
                
                if x_diff < 80 and y_diff < 30:  # Within 80pts x, 30pts y
                    distance = (x_diff ** 2 + y_diff ** 2) ** 0.5
                    if distance < min_distance:
                        min_distance = distance
                        closest_box = box
            
            if closest_box:
                # Place text at center of box, slightly above the line
                text_x = closest_box['x0'] + 5  # Small offset from left
                text_y = closest_box['top'] + 3  # Slightly above the bottom line
                field_positions[label_name] = (text_x, text_y)
                print(f"{label_name}: box at y={closest_box['top']:.1f}, text at ({text_x:.1f}, {text_y:.1f})")
            else:
                print(f"{label_name}: No matching box found")
        
        print(f"\n=== FINAL FIELD POSITIONS ===")
        for field, (x, y) in field_positions.items():
            print(f"{field}: ({x:.1f}, {y:.1f})")
            
    except Exception as e:
        print(f"Error finding boxes: {e}")
        import traceback
        traceback.print_exc()
