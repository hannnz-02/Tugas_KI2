import socket
import secrets
import json
from aes_manual import encrypt_cbc, send_json, recv_json

KDC_IP = "127.0.0.1"
KDC_PORT = 5000

KEY_A = b"AliceKey12345678"
KEY_B = b"BobKey1234567890"


def encrypt_packet(key, data):
    text = json.dumps(data, separators=(",", ":")).encode("ascii")
    return encrypt_cbc(key, text).hex()


def handle_client(conn, address):
    try:
        request = recv_json(conn)

        if request is None or request.get("type") != "REQUEST_KEY":
            send_json(conn, {
                "status": "ERROR",
                "message": "Request tidak dikenal"
            })
            return

        session_key = secrets.token_bytes(16)

        print("\nPermintaan session key dari:", address[0])
        print("Session key baru dibuat:", session_key.hex())

        packet_alice = {
            "session_key": session_key.hex(),
            "alice": "Alice",
            "bob": "Bob"
        }

        ticket_bob = {
            "session_key": session_key.hex(),
            "alice": "Alice",
            "bob": "Bob"
        }

        response = {
            "status": "OK",
            "alice_packet": encrypt_packet(KEY_A, packet_alice),
            "bob_ticket": encrypt_packet(KEY_B, ticket_bob)
        }

        send_json(conn, response)

        print("Paket terenkripsi dikirim kepada Alice.")
        print("Tiket terenkripsi untuk Bob disertakan.")

    except Exception as e:
        print("Kesalahan KDC:", e)

    finally:
        conn.close()


def main():
    print("KDC berjalan pada port", KDC_PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((KDC_IP, KDC_PORT))
        server.listen()

        while True:
            conn, address = server.accept()
            handle_client(conn, address)


if __name__ == "__main__":
    main()