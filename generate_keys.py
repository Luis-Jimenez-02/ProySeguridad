import crypto_utils

# Generar llaves pública y privada
private_key, public_key = crypto_utils.generate_keys()

# Guardar las llaves en archivos
crypto_utils.save_key(private_key, "private_key.pem", is_private=True)
crypto_utils.save_key(public_key, "public_key.pem")

print("Llaves generadas y guardadas como 'private_key.pem' y 'public_key.pem'")
