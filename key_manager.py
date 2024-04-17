from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key(
    private_key_path: str = "private_key.pem",
) -> rsa.RSAPrivateKey | None:
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        return private_key

    except Exception:
        return None


def generate_public_key(
    private_key_path: str = "private_key.pem", public_key_path: str = "public_key.pem"
) -> rsa.RSAPublicKey | None:
    try:
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(), password=None
            )

        public_key = private_key.public_key()

        with open(public_key_path, "wb") as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        return public_key

    except Exception:
        return None
