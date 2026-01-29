#!/usr/bin/env python3
"""
Secure File Delete Utility

Production-grade secure file deletion with multiple overwrite passes.
Implements DoD 5220.22-M standard for data sanitization.
"""

import os
import sys
import argparse
import random
from pathlib import Path
from typing import List


class SecureDelete:
    """Secure file deletion utility"""
    
    # DoD 5220.22-M patterns
    DOD_PATTERNS = [
        lambda size: b'\x00' * size,  # Pass 1: All zeros
        lambda size: b'\xFF' * size,  # Pass 2: All ones
        lambda size: os.urandom(size)  # Pass 3: Random data
    ]
    
    # Gutmann method (35 passes) - subset
    GUTMANN_PATTERNS = [
        lambda size: bytes([0x55] * size),
        lambda size: bytes([0xAA] * size),
        lambda size: bytes([0x92, 0x49, 0x24] * (size // 3 + 1))[:size],
        lambda size: bytes([0x49, 0x24, 0x92] * (size // 3 + 1))[:size],
        lambda size: bytes([0x24, 0x92, 0x49] * (size // 3 + 1))[:size],
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Print message if verbose"""
        if self.verbose:
            print(f"  {message}")
    
    def secure_overwrite(self, filepath: str, passes: int = 3, 
                        method: str = 'dod') -> bool:
        """
        Securely overwrite file with multiple passes
        
        Args:
            filepath: File to overwrite
            passes: Number of overwrite passes
            method: 'dod' (3-pass), 'gutmann' (35-pass), or 'random'
            
        Returns:
            True if successful
        """
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            if file_size == 0:
                self.log(f"File is empty, skipping overwrite")
                return True
            
            # Select overwrite patterns
            if method == 'gutmann':
                patterns = self.GUTMANN_PATTERNS * (passes // len(self.GUTMANN_PATTERNS) + 1)
                patterns = patterns[:passes]
            elif method == 'dod':
                patterns = self.DOD_PATTERNS * (passes // len(self.DOD_PATTERNS) + 1)
                patterns = patterns[:passes]
            else:  # random
                patterns = [lambda size: os.urandom(size)] * passes
            
            # Perform overwrite passes
            with open(filepath, 'r+b') as f:
                for pass_num, pattern_func in enumerate(patterns, 1):
                    self.log(f"Pass {pass_num}/{len(patterns)}: Writing pattern...")
                    
                    # Seek to beginning
                    f.seek(0)
                    
                    # Write pattern in chunks for large files
                    chunk_size = 64 * 1024  # 64KB chunks
                    remaining = file_size
                    
                    while remaining > 0:
                        write_size = min(chunk_size, remaining)
                        pattern = pattern_func(write_size)
                        f.write(pattern)
                        remaining -= write_size
                    
                    # Flush to disk
                    f.flush()
                    os.fsync(f.fileno())
            
            self.log("Overwrite complete")
            return True
            
        except Exception as e:
            self.log(f"Error during overwrite: {e}")
            return False
    
    def secure_delete_file(self, filepath: str, passes: int = 3, 
                          method: str = 'dod', shred_name: bool = True) -> bool:
        """
        Securely delete a file
        
        Args:
            filepath: File to delete
            passes: Number of overwrite passes
            method: Overwrite method
            shred_name: Also randomize filename before deletion
            
        Returns:
            True if successful
        """
        if not os.path.isfile(filepath):
            self.log(f"Not a file: {filepath}")
            return False
        
        self.log(f"Securely deleting: {filepath}")
        
        # Step 1: Overwrite file contents
        if not self.secure_overwrite(filepath, passes, method):
            return False
        
        # Step 2: Rename file to random name
        if shred_name:
            directory = os.path.dirname(filepath) or '.'
            random_name = os.path.join(
                directory,
                ''.join(random.choices('0123456789abcdef', k=16))
            )
            
            try:
                os.rename(filepath, random_name)
                filepath = random_name
                self.log(f"Renamed to: {os.path.basename(random_name)}")
            except Exception as e:
                self.log(f"Warning: Could not rename file: {e}")
        
        # Step 3: Delete file
        try:
            os.remove(filepath)
            self.log("File deleted")
            return True
        except Exception as e:
            self.log(f"Error deleting file: {e}")
            return False
    
    def secure_delete_directory(self, dirpath: str, passes: int = 3, 
                               method: str = 'dod') -> int:
        """
        Securely delete all files in directory
        
        Args:
            dirpath: Directory to process
            passes: Number of overwrite passes
            method: Overwrite method
            
        Returns:
            Number of files deleted
        """
        if not os.path.isdir(dirpath):
            self.log(f"Not a directory: {dirpath}")
            return 0
        
        deleted_count = 0
        
        # Walk directory tree
        for root, dirs, files in os.walk(dirpath, topdown=False):
            # Delete files
            for filename in files:
                filepath = os.path.join(root, filename)
                if self.secure_delete_file(filepath, passes, method):
                    deleted_count += 1
            
            # Remove empty directories
            for dirname in dirs:
                dirpath_full = os.path.join(root, dirname)
                try:
                    os.rmdir(dirpath_full)
                    self.log(f"Removed directory: {dirpath_full}")
                except Exception as e:
                    self.log(f"Could not remove directory {dirpath_full}: {e}")
        
        # Remove the root directory
        try:
            os.rmdir(dirpath)
            self.log(f"Removed directory: {dirpath}")
        except Exception as e:
            self.log(f"Could not remove directory {dirpath}: {e}")
        
        return deleted_count
    
    def secure_wipe_free_space(self, directory: str = '.') -> bool:
        """
        Wipe free space in directory (fills free space with random data)
        
        Args:
            directory: Directory to wipe free space in
            
        Returns:
            True if successful
        """
        self.log("Wiping free space...")
        
        try:
            # Create temporary file
            temp_file = os.path.join(directory, '.wipe_temp_file')
            
            # Fill free space
            chunk_size = 1024 * 1024  # 1MB chunks
            with open(temp_file, 'wb') as f:
                try:
                    while True:
                        f.write(os.urandom(chunk_size))
                        f.flush()
                except OSError:
                    # Disk full
                    pass
            
            # Delete temp file
            os.remove(temp_file)
            self.log("Free space wiped")
            return True
            
        except Exception as e:
            self.log(f"Error wiping free space: {e}")
            return False


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Securely delete files with multiple overwrite passes',
        epilog='Methods: dod (3-pass), gutmann (35-pass), random'
    )
    parser.add_argument('path', help='File or directory to delete')
    parser.add_argument('-p', '--passes', type=int, default=3,
                       help='Number of overwrite passes (default: 3)')
    parser.add_argument('-m', '--method', choices=['dod', 'gutmann', 'random'],
                       default='dod', help='Overwrite method (default: dod)')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process directories recursively')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-shred-name', action='store_true',
                       help="Don't randomize filename before deletion")
    parser.add_argument('--wipe-free-space', action='store_true',
                       help='Wipe free space after deletion')
    
    args = parser.parse_args()
    
    # Create secure delete instance
    sd = SecureDelete(verbose=args.verbose)
    
    # Check if path exists
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    print(f"Secure Delete Utility")
    print(f"Path: {args.path}")
    print(f"Method: {args.method} ({args.passes} passes)")
    
    # Confirmation
    response = input(f"\nAre you sure you want to PERMANENTLY delete '{args.path}'? (yes/no): ")
    if response.lower() != 'yes':
        print("Operation cancelled")
        sys.exit(0)
    
    print("\nProcessing...")
    
    # Process file or directory
    if os.path.isfile(args.path):
        success = sd.secure_delete_file(
            args.path,
            passes=args.passes,
            method=args.method,
            shred_name=not args.no_shred_name
        )
        
        if success:
            print(f"\n✓ File securely deleted")
        else:
            print(f"\n✗ Failed to delete file")
            sys.exit(1)
    
    elif os.path.isdir(args.path):
        if not args.recursive:
            print("Error: Use --recursive flag to delete directories")
            sys.exit(1)
        
        deleted_count = sd.secure_delete_directory(
            args.path,
            passes=args.passes,
            method=args.method
        )
        
        print(f"\n✓ Deleted {deleted_count} files")
    
    # Wipe free space if requested
    if args.wipe_free_space:
        print("\nWiping free space...")
        directory = os.path.dirname(args.path) or '.'
        sd.secure_wipe_free_space(directory)
    
    print("\n✓ Secure deletion complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
