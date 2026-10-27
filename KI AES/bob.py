import socket
import json
from aes_manual import encrypt_cbc, decrypt_cbc, send_json, recv_json

BOB_IP = "0.0.0.0"
BOB_PORT = 6000

KEY_B = b"BobKey1234567890"


def encrypt_packet(key, data):
    text = json.dumps(data, separators=(",", ":")).encode("ascii")
    return encrypt_cbc(key, text).hex()


def decrypt_packet(key, cipher_hex):
    raw = decrypt_cbc(key, bytes.fromhex(cipher_hex))
    return json.loads(raw.decode("ascii"))


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((BOB_IP, BOB_PORT))
        server.listen(1)

        print("Bob menunggu koneksi Alice...")

        conn, address = server.accept()

        with conn:
            print("Alice terhubung:", address)

            data = recv_json(conn)

            if data is None or "ticket" not in data:
                print("Tiket Bob tidak diterima.")
                return

            ticket = decrypt_packet(KEY_B, data["ticket"])
            session_key = bytes.fromhex(ticket["session_key"])

            send_json(conn, {"status": "READY"})

            print("Session key berhasil diterima.")
            print("Bob siap menerima pesan Alice.")

            while True:
                data = recv_json(conn)

                if data is None:
                    print("Koneksi Alice terputus.")
                    break

                if data.get("type") == "QUIT":
                    print("Alice mengakhiri percakapan.")
                    break

                if data.get("type") != "MESSAGE":
                    continue

                message = decrypt_packet(
                    session_key, data["ciphertext"]
                )

                print("\nAlice:", message["text"])
                print("Ciphertext Alice (Hex):", data["ciphertext"])

                reply = input("\nBob: ")

                if reply == "/quit":
                    send_json(conn, {"type": "QUIT"})
                    print("Bob mengakhiri percakapan.")
                    break

                ciphertext = encrypt_packet(
                    session_key, {"text": reply}
                )

                print("Ciphertext Bob (Hex):", ciphertext)

                send_json(conn, {
                    "type": "MESSAGE",
                    "ciphertext": ciphertext
                })

                print("Balasan terkirim. Menunggu pesan Alice berikutnya...")


if __name__ == "__main__":
    main()
