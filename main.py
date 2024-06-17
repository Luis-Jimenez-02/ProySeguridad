import os
import socket
import crypto_utils
from PIL import Image
from scapy.all import ARP, Ether, srp
import paramiko

def get_mac_address(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        return None

def hide_message(input_image_path, output_image_path, message):
    try:
        img = Image.open(input_image_path)
        hex_message = message.hex()
        img.putdata([(int(hex_message[i:i+2], 16),) for i in range(0, len(hex_message), 2)])
        img.save(output_image_path)
    except Exception as e:
        print(f"Error al ocultar el mensaje: {e}")

def extract_message(image_path):
    try:
        img = Image.open(image_path)
        data = img.getdata()
        extracted_message = b"".join([bytes([d[0]]) for d in data])
        return extracted_message
    except Exception as e:
        print(f"Error al extraer el mensaje: {e}")
        return None

def transfer_file_via_ssh(ip, port, username, password, local_file_path, remote_file_path):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("Conectando al servidor SSH...")
        ssh.connect(ip, port=port, username=username, password=password)
        print("Conexión SSH exitosa.")
        sftp = ssh.open_sftp()
        print(f"Transfiriendo el archivo {local_file_path} a {remote_file_path}...")
        sftp.put(local_file_path, remote_file_path)
        sftp.close()
        ssh.close()
        print(f"Archivo transferido exitosamente a {ip}:{remote_file_path}")
    except paramiko.SSHException as e:
        print(f"Error en la conexión SSH: {e}")
    except FileNotFoundError as e:
        print(f"Error en la transferencia de archivos: Archivo no encontrado - {e}")
    except PermissionError as e:
        print(f"Error en la transferencia de archivos: Permisos insuficientes - {e}")
    except Exception as e:
        print(f"Error en la transferencia de archivos: {e}")

def send_message():
    recipient_ip = input("Ingrese la IP del receptor: ")
    recipient_mac = get_mac_address(recipient_ip)
    if recipient_mac:
        print(f"MAC Address del receptor: {recipient_mac}")
    else:
        print("No se pudo obtener la MAC Address del receptor.")
        return

    public_key_filename = input("Ingrese el nombre del archivo de la llave pública del receptor: ")
    public_key = crypto_utils.load_key(public_key_filename)

    choice = input("¿Desea ingresar un mensaje (1) o seleccionar un archivo (2)? ")
    if choice == '1':
        message = input("Ingrese su mensaje: ").encode()
    elif choice == '2':
        file_path = input("Ingrese la ruta del archivo: ")
        with open(file_path, 'rb') as f:
            message = f.read()

    sha384_hash = crypto_utils.hash_sha384(message)
    print(f"SHA-384 Hash: {sha384_hash.hex()}")

    encrypted_message = crypto_utils.encrypt_message(message, public_key)
    print(f"Mensaje encriptado: {encrypted_message}")

    sha512_hash = crypto_utils.hash_sha512(encrypted_message)
    print(f"SHA-512 Hash: {sha512_hash.hex()}")

    input_image_path = input("Ingrese la ruta de la imagen de entrada: ")
    output_image_path = input("Ingrese la ruta de la imagen de salida: ")
    hide_message(input_image_path, output_image_path, encrypted_message)

    with open(output_image_path, 'rb') as f:
        image_data = f.read()
    blake2_hash = crypto_utils.hash_blake2b(image_data)
    print(f"Blake2 Hash: {blake2_hash.hex()}")

    remote_path = input("Ingrese la ruta de destino en el receptor: ") + "/" + os.path.basename(output_image_path)
    ssh_ip = input("Ingrese la IP del servidor SSH: ")
    ssh_port = int(input("Ingrese el puerto SSH: "))
    ssh_username = input("Ingrese el nombre de usuario SSH: ")
    ssh_password = input("Ingrese la contraseña SSH: ")

    transfer_file_via_ssh(ssh_ip, ssh_port, ssh_username, ssh_password, output_image_path, remote_path)

    print("Mensaje oculto en la imagen y preparado para ser enviado.")
    return output_image_path, blake2_hash, sha384_hash, sha512_hash

def receive_message(expected_blake2_hash, expected_sha384_hash, expected_sha512_hash):
    input_image_path = input("Ingrese la ruta de la imagen recibida: ")

    with open(input_image_path, 'rb') as f:
        image_data = f.read()
    received_blake2_hash = crypto_utils.hash_blake2b(image_data)
    if received_blake2_hash != expected_blake2_hash:
        print("Error: El hash Blake2 no coincide. El mensaje podría haber sido alterado.")
        os.remove(input_image_path)
        return

    encrypted_message = extract_message(input_image_path)

    received_sha512_hash = crypto_utils.hash_sha512(encrypted_message)
    if received_sha512_hash != expected_sha512_hash:
        print("Error: El hash SHA-512 no coincide. El mensaje podría haber sido alterado.")
        os.remove(input_image_path)
        return

    private_key_filename = input("Ingrese el nombre del archivo de la llave privada: ")
    private_key = crypto_utils.load_key(private_key_filename, is_private=True)
    decrypted_message = crypto_utils.decrypt_message(encrypted_message, private_key)

    received_sha384_hash = crypto_utils.hash_sha384(decrypted_message)
    if received_sha384_hash != expected_sha384_hash:
        print("Error: El hash SHA-384 no coincide. El mensaje podría haber sido alterado.")
        os.remove(input_image_path)
        return

    print("Mensaje recibido y verificado:")
    print(decrypted_message.decode('latin-1'))

if __name__ == "__main__":
    choice = input("¿Desea enviar un mensaje (1) o recibir un mensaje (2)? ")
    if choice == '1':
        output_image_path, blake2_hash, sha384_hash, sha512_hash = send_message()
    elif choice == '2':
        expected_blake2_hash = input("Ingrese el hash Blake2 esperado: ")
        expected_sha384_hash = input("Ingrese el hash SHA-384 esperado: ")
        expected_sha512_hash = input("Ingrese el hash SHA-512 esperado: ")
        receive_message(bytes.fromhex(expected_blake2_hash), bytes.fromhex(expected_sha384_hash), bytes.fromhex(expected_sha512_hash))
