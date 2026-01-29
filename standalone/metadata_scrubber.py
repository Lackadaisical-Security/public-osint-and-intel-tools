#!/usr/bin/env python3
"""
Metadata Scrubber

Standalone tool to remove metadata from files before sharing.
Supports images (EXIF), PDFs, Office documents, and more.
"""

import os
import sys
import argparse
import shutil
from pathlib import Path
from typing import List, Dict, Optional
import tempfile


class MetadataScrubber:
    """Remove metadata from various file types"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = {
            'processed': 0,
            'failed': 0,
            'skipped': 0
        }
    
    def log(self, message: str) -> None:
        """Print message if verbose"""
        if self.verbose:
            print(f"  {message}")
    
    def scrub_image_exif(self, filepath: str, output_path: Optional[str] = None) -> bool:
        """
        Remove EXIF metadata from images
        
        Args:
            filepath: Input image file
            output_path: Output file (if None, overwrites original)
            
        Returns:
            True if successful
        """
        try:
            from PIL import Image
            
            # Open image
            img = Image.open(filepath)
            
            # Create output path
            if output_path is None:
                output_path = filepath
            
            # Get format
            img_format = img.format
            
            # Save without EXIF data
            # For JPEG, explicitly remove EXIF
            if img_format in ['JPEG', 'JPG']:
                # Create new image without metadata
                data = list(img.getdata())
                image_without_exif = Image.new(img.mode, img.size)
                image_without_exif.putdata(data)
                image_without_exif.save(output_path, img_format, quality=95)
            else:
                # For other formats, save without info
                img.save(output_path, img_format)
            
            self.log(f"Scrubbed EXIF from: {filepath}")
            return True
            
        except ImportError:
            print("Error: Pillow library required for image processing")
            print("Install: pip install Pillow")
            return False
        except Exception as e:
            self.log(f"Error scrubbing {filepath}: {e}")
            return False
    
    def scrub_pdf_metadata(self, filepath: str, output_path: Optional[str] = None) -> bool:
        """
        Remove metadata from PDF files
        
        Args:
            filepath: Input PDF file
            output_path: Output file (if None, overwrites original)
            
        Returns:
            True if successful
        """
        try:
            import PyPDF2
            
            if output_path is None:
                output_path = filepath + '.tmp'
                replace_original = True
            else:
                replace_original = False
            
            # Read PDF
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                writer = PyPDF2.PdfWriter()
                
                # Copy pages without metadata
                for page in reader.pages:
                    writer.add_page(page)
                
                # Write to output
                with open(output_path, 'wb') as out_f:
                    writer.write(out_f)
            
            if replace_original:
                shutil.move(output_path, filepath)
            
            self.log(f"Scrubbed PDF metadata from: {filepath}")
            return True
            
        except ImportError:
            print("Error: PyPDF2 library required for PDF processing")
            print("Install: pip install PyPDF2")
            return False
        except Exception as e:
            self.log(f"Error scrubbing PDF {filepath}: {e}")
            return False
    
    def scrub_office_metadata(self, filepath: str, output_path: Optional[str] = None) -> bool:
        """
        Remove metadata from Office documents (basic approach)
        
        Note: For full Office metadata removal, use python-docx or openpyxl
        This is a simplified version that requires external tools
        
        Args:
            filepath: Input Office file
            output_path: Output file (if None, overwrites original)
            
        Returns:
            True if successful
        """
        self.log(f"Office document metadata removal requires specialized libraries")
        self.log(f"For .docx: pip install python-docx")
        self.log(f"For .xlsx: pip install openpyxl")
        self.log(f"Skipping: {filepath}")
        return False
    
    def scrub_file(self, filepath: str, output_path: Optional[str] = None) -> bool:
        """
        Scrub metadata from file based on extension
        
        Args:
            filepath: Input file
            output_path: Output file (if None, overwrites original)
            
        Returns:
            True if successful
        """
        ext = Path(filepath).suffix.lower()
        
        # Image files
        if ext in ['.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.gif']:
            return self.scrub_image_exif(filepath, output_path)
        
        # PDF files
        elif ext == '.pdf':
            return self.scrub_pdf_metadata(filepath, output_path)
        
        # Office documents
        elif ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']:
            return self.scrub_office_metadata(filepath, output_path)
        
        else:
            self.log(f"Unsupported file type: {ext}")
            return False
    
    def scrub_directory(self, directory: str, output_dir: Optional[str] = None, 
                       recursive: bool = False) -> Dict[str, int]:
        """
        Scrub all supported files in directory
        
        Args:
            directory: Input directory
            output_dir: Output directory (if None, overwrites originals)
            recursive: Process subdirectories
            
        Returns:
            Statistics dict
        """
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        pattern = '**/*' if recursive else '*'
        
        for filepath in Path(directory).glob(pattern):
            if filepath.is_file():
                # Determine output path
                if output_dir:
                    rel_path = filepath.relative_to(directory)
                    out_path = Path(output_dir) / rel_path
                    os.makedirs(out_path.parent, exist_ok=True)
                    out_path = str(out_path)
                else:
                    out_path = None
                
                # Scrub file
                if self.scrub_file(str(filepath), out_path):
                    self.stats['processed'] += 1
                else:
                    self.stats['failed'] += 1
        
        return self.stats


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Remove metadata from files',
        epilog='Supported: Images (EXIF), PDFs. Office docs require additional libraries.'
    )
    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file or directory')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process directories recursively')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create scrubber
    scrubber = MetadataScrubber(verbose=args.verbose)
    
    input_path = Path(args.input)
    
    # Check if input exists
    if not input_path.exists():
        print(f"Error: Input path not found: {args.input}")
        sys.exit(1)
    
    print(f"Metadata Scrubber")
    print(f"Input: {args.input}")
    if args.output:
        print(f"Output: {args.output}")
    print()
    
    # Process file or directory
    if input_path.is_file():
        success = scrubber.scrub_file(str(input_path), args.output)
        if success:
            print(f"✓ Successfully scrubbed: {args.input}")
            sys.exit(0)
        else:
            print(f"✗ Failed to scrub: {args.input}")
            sys.exit(1)
    
    elif input_path.is_dir():
        stats = scrubber.scrub_directory(
            str(input_path), 
            args.output, 
            args.recursive
        )
        
        print(f"\nResults:")
        print(f"  Processed: {stats['processed']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Skipped: {stats['skipped']}")
        
        if stats['failed'] > 0:
            sys.exit(1)
        else:
            print(f"\n✓ All files processed successfully")
            sys.exit(0)
    
    else:
        print(f"Error: Invalid input path")
        sys.exit(1)


if __name__ == "__main__":
    main()
