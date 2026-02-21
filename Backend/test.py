import bcrypt

hash_from_db = b"$2b$12$Rb9JZ9D1v7dz1VKt8Psrwee2JQdjDQbVeMesiAWgJi3aIgKotytdC"
print(bcrypt.checkpw("admin123".encode(), hash_from_db))