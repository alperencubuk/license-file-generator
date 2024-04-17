from key_manager import generate_private_key, generate_public_key
from license_manager import generate_license, validate_licence


def test_license() -> None:
    if generate_private_key():
        print("Private key generated successfully.")
        if generate_public_key():
            print("Public key generated successfully.")
        else:
            print("Public key generation failed.")
    else:
        print("Private key generation failed.")

    if generate_license():
        print("License created successfully.")
        if validate_licence():
            print("License is valid.")
        else:
            print("License is invalid.")
    else:
        print("License creation failed.")


if __name__ == "__main__":
    test_license()
