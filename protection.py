import base64
import hashlib
import os
import sys
import time
from datetime import datetime

class CodeProtection:
    def __init__(self):
        self.signature = "PEGASUS_SCAN_WEB_TOTAL_BY_SOBRI"
        # Hash of the key "sobri" already stored to make activation simpler
        self.key = "62c50d275cd545cc8f9551dcb7b997a45c702e03465191fcbd3a542e0695c9fa"
        self.checksum = None
    
    def calculate_file_hash(self, filename):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def verify_integrity(self, main_file="main.py"):
        """Verify the integrity of the main script"""
        # In development mode, always pass integrity check
        # To enable strict verification, change this to False
        development_mode = False
        
        if development_mode:
            # Always pass in development mode
            # Just update the hash file
            current_hash = self.calculate_file_hash(main_file)
            if current_hash:
                hash_file = ".pegasus_hash"
                with open(hash_file, "w") as f:
                    f.write(current_hash)
            return True
            
        # Regular integrity check for production mode
        if not os.path.exists(main_file):
            print("\033[91m[ERROR] Main script file not found!\033[0m")
            return False

        current_hash = self.calculate_file_hash(main_file)
        if not current_hash:
            print("\033[91m[ERROR] Failed to calculate file hash!\033[0m")
            return False

        # Store hash on first run
        hash_file = ".pegasus_hash"
        if not os.path.exists(hash_file):
            with open(hash_file, "w") as f:
                f.write(current_hash)
            return True

        # Verify hash on subsequent runs
        try:
            with open(hash_file, "r") as f:
                stored_hash = f.read().strip()
            
            if current_hash != stored_hash:
                print("\033[91m[ERROR] Code integrity check failed!")
                print("The source code has been modified!")
                print("Please obtain a fresh copy of the script.\033[0m")
                return False
                
            return True
        except Exception:
            print("\033[91m[ERROR] Failed to verify code integrity!\033[0m")
            return False

    def verify_license(self):
        """Verify the license key"""
        print("\033[96m[*] Verifying license...\033[0m")
        activation_key = input("\033[93m[?] Enter activation key: \033[0m")
        
        # Accept direct "sobri" as key for simplicity
        if activation_key.lower() == "sobri":
            print("\033[92m[+] License activated successfully!\033[0m")
            return True
            
        # Also check hashed key for backward compatibility
        input_hash = hashlib.sha256(activation_key.encode()).hexdigest()
        if input_hash == self.key:
            print("\033[92m[+] License activated successfully!\033[0m")
            return True
            
        print("\033[91m[-] Invalid license key!")
        print("Please contact the author:")
        print("Email: muhammadsobrimaulana31@gmail.com")
        print("GitHub: github.com/sobri3195\033[0m")
        return False

    def start_protection(self):
        """Main protection routine"""
        print("\033[96m[*] Initializing Pegasus protection...\033[0m")
        
        if not self.verify_integrity():
            sys.exit(1)
            
        if not self.verify_license():
            sys.exit(1)
            
        print("\033[92m[+] Protection checks passed!\033[0m")
        return True

# Anti-debug and anti-tampering measures
def detect_debugging():
    """Detect if the script is being debugged"""
    # Disable for development
    return
    
    import traceback
    try:
        if sys.gettrace() is not None:
            print("\033[91m[ERROR] Debugging detected! Execution halted.\033[0m")
            sys.exit(1)
    except Exception:
        pass

def prevent_modification():
    """Prevent modification of the source code"""
    try:
        import py_compile
        py_compile.compile("main.py")
    except Exception:
        pass

if __name__ == "__main__":
    protection = CodeProtection()
    protection.start_protection() 