import os

def create_keys() -> None:
    
    # --- Create group key ---
    GROUP_KEY = os.urandom(16)

    # --- Save group key ---
    with open("keys/group_key.bin", "wb") as f:
        f.write(GROUP_KEY)
    print("GROUP_KEY aangemaakt.")

if __name__ == "__main__":
    os.system('cls')
    create_keys()