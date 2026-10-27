import socket
import json
from aes_manual import encrypt_cbc, decrypt_cbc, send_json, recv_json

KDC_IP = "127.0.0.1"
KDC_PORT = 5000

BOB_IP = "127.0.0.1"
BOB_PORT = 6000

KEY_A = b"AliceKey12345678"


def encrypt_packet(key, data):
    text = json.dumps(data, separators=(",", ":")).encode("ascii")
    return encrypt_cbc(key, text).hex()


def decrypt_packet(key, cipher_hex):
    raw = decrypt_cbc(key, bytes.fromhex(cipher_hex))
    return json.loads(raw.decode("ascii"))


def main():
    # Meminta session key dari KDC
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KDC_IP, KDC_PORT))

        send_json(s, {"type": "REQUEST_KEY"})
        response = recv_json(s)

    if response is None or response.get("status") != "OK":
        print("Gagal meminta session key dari KDC:", response)
        return

    packet = decrypt_packet(KEY_A, response["alice_packet"])
    session_key = bytes.fromhex(packet["session_key"])

    print("Session key berhasil diterima dari KDC.")

    # Menghubungkan Alice ke Bob
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BOB_IP, BOB_PORT))

        send_json(s, {"ticket": response["bob_ticket"]})

        ready = recv_json(s)

        if ready is None or ready.get("status") != "READY":
            print("Bob belum siap.")
            return

        print("Terhubung dengan Bob.")
        print("Ketik /quit untuk keluar.")

        while True:
            message = input("\nAlice: ")

            if message == "/quit":
                send_json(s, {"type": "QUIT"})
                print("Alice mengakhiri percakapan.")
                break

            ciphertext = encrypt_packet(
                session_key, {"text": message}
            )

            print("Ciphertext Alice (Hex):", ciphertext)

            send_json(s, {
                "type": "MESSAGE",
                "ciphertext": ciphertext
            })

            # Alice wajib menunggu balasan Bob
            print("Menunggu balasan Bob...")

            response = recv_json(s)

            if response is None:
                print("Koneksi dengan Bob terputus.")
                break

            if response.get("type") == "QUIT":
                print("Bob mengakhiri percakapan.")
                break

            if response.get("type") != "MESSAGE":
                print("Format balasan Bob tidak dikenal:", response)
                break

            reply = decrypt_packet(
                session_key, response["ciphertext"]
            )

            print("\nBob:", reply["text"])
            print("Ciphertext Bob (Hex):", response["ciphertext"])
            print("Balasan diterima.")


if __name__ == "__main__":
    main()
