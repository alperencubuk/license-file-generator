from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def generate_license(
    private_key_path: str = "private_key.pem",
    license_path: str = "license.lic",
    expire_date: str = "2030-01-01",
    product_name: str = "Product Name",
    company_name: str = "Company Name",
    license_type: str = "Commercial",
) -> bool:
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        license_info = (
            "-----BEGIN LICENSE-----\n"
            f"Product: {product_name}\n"
            f"License Owner: {company_name}\n"
            f"License Type: {license_type}\n"
            f"Expire Date: {expire_date}\n"
        )

        signature = private_key.sign(
            license_info.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        with open(license_path, "w") as f:
            f.write(license_info)
            f.write(f"Signature: {signature.hex()}\n-----END LICENSE-----\n")

        return True

    except Exception:
        return False


def validate_licence(
    public_key_path: str = "public_key.pem", license_path: str = "license.lic"
) -> bool:
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(license_path, "r") as license_file:
            licence_info, signature = license_file.read().split("Signature: ")

        public_key.verify(
            bytes.fromhex(signature.split("\n")[0].strip()),
            licence_info.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        expire_date = datetime.strptime(
            licence_info.split("Expire Date: ")[1].split("\n")[0].strip(), "%Y-%m-%d"
        )

        if expire_date < datetime.now():
            return False

        return True

    except Exception:
        return False
