from steganography.steganography import Steganography

def hide_message(input_image_path, output_image_path, message):
    Steganography.encode(input_image_path, output_image_path, message)

def extract_message(image_path):
    return Steganography.decode(image_path)
