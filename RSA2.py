import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

# Step 1: Generate RSA key pair for Certificate Authority (CA)
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Save RSA keys in PEM format
def save_key_pem(private_key, public_key, private_file, public_file):
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(private_file, "wb") as priv_file:
        priv_file.write(pem_private)
    with open(public_file, "wb") as pub_file:
        pub_file.write(pem_public)

# Step 3: Load RSA private key from a file selected through a dialog
def load_private_key():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    private_file = filedialog.askopenfilename(
        title="Select the private key file",
        filetypes=[("PEM files", "*.pem")]
    )
    
    if private_file:  # If a file was selected
        with open(private_file, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    else:
        print("No file selected.")
        return None

# Step 4: Load two image files selected through a dialog
def load_image_files():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    image_files = filedialog.askopenfilenames(
        title="Select two image files",
        filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")]
    )
    
    if len(image_files) == 2:  # Ensure exactly two files are selected
        images_data = []
        for image_file in image_files:
            with open(image_file, "rb") as file:
                images_data.append(file.read())  # Read each image's binary data
        print(f"Image files '{image_files[0]}' and '{image_files[1]}' loaded successfully.")
        return images_data
    else:
        print("Please select exactly two image files.")
        return None

# Step 5: Sign certificate (in this case image data) with CA's private key
def sign_certificate(private_key, certificate_data):
    signature = private_key.sign(
        certificate_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature)  # Encode to base64 for easy transmission

# Step 6: Verify the signature using CA's public key
def verify_signature(public_key, certificate_data, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            certificate_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Step 7: Compare two images (raw data)
def compare_images(image_data_1, image_data_2):
    return image_data_1 == image_data_2

# Example usage
if __name__ == "__main__":
    # Generate CA keys
    ca_private_key, ca_public_key = generate_rsa_keypair()

    # Save the keys (optional)
    save_key_pem(ca_private_key, ca_public_key, "ca_private.pem", "ca_public.pem")

    # Load private key using file dialog
    loaded_private_key = load_private_key()

    # Load two image files using file dialog
    images_data = load_image_files()
    
    if loaded_private_key and images_data:
        # Sign the first image data
        signature_1 = sign_certificate(loaded_private_key, images_data[0])
        print(f"Signature for first image (Base64 Encoded):\n{signature_1.decode()}\n")

        # Sign the second image data
        signature_2 = sign_certificate(loaded_private_key, images_data[1])
        print(f"Signature for second image (Base64 Encoded):\n{signature_2.decode()}\n")

        # Verification with public key for first image
        is_valid_1 = verify_signature(ca_public_key, images_data[0], signature_1)
        print(f"Signature valid for first image: {is_valid_1}")

        # Verification with public key for second image
        is_valid_2 = verify_signature(ca_public_key, images_data[1], signature_2)
        print(f"Signature valid for second image: {is_valid_2}")

        # Compare the two image data directly
        are_images_equal = compare_images(images_data[0], images_data[1])
        if are_images_equal:
            print("The two images are identical.")
        else:
            print("The two images are different.")
    else:
        print("Failed to load the private key or image files.")
