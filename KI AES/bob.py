
import socket
import threading

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    decrypt_json_hex,
    encrypt_text_hex,
    decrypt_text_hex,
)

# Konfigurasi Bob
KDC_IP = "192.168.43.129"
KDC_PORT = 5000
BOB_IP = "0.0.0.0"
BOB_PORT = 5001
ALICE_IP = "192.168.43.131"
ALICE_PORT = 5001

KB = b"FEDCBA0987654321"


def terima_pesan(conn, session_key):
    while True:
        try:
            data = recv_json(conn)

            if data.get("type") == "CHAT":
                plaintext = decrypt_text_hex(
                    session_key, data["cipher_hex"]
                )
                print(f"\n{data['sender']}: {plaintext}")

            elif data.get("type") == "CHAT_QUIT":
                print("\nAlice mengakhiri sesi.")
                break

        except Exception:
            print("\nKoneksi berakhir.")
            break


def komunikasi(conn, session_key):
    threading.Thread(
        target=terima_pesan,
        args=(conn, session_key),
        daemon=True
    ).start()

    while True:
        try:
            pesan = input("Bob: ")

            if pesan == "/quit":
                send_json(conn, {"type": "CHAT_QUIT"})
                break

            pesan.encode("ascii")

            ciphertext = encrypt_text_hex(
                session_key, pesan
            )

            send_json(conn, {
                "type": "CHAT",
                "sender": "Bob",
                "cipher_hex": ciphertext
            })

            print("Ciphertext Hex:", ciphertext)

        except UnicodeEncodeError:
            print("Gunakan karakter ASCII.")
        except Exception as error:
            print("Koneksi berakhir:", error)
            break


def layani_alice(conn, addr):
    with conn:
        try:
            tiket = recv_json(conn)

            if tiket.get("type") != "TICKET":
                return

            data_tiket = decrypt_json_hex(
                KB, tiket["ticket_hex"]
            )

            session_key = data_tiket["KS"].encode("ascii")

            n2 = __import__("secrets").token_hex(8)

            send_json(conn, {
                "type": "CHALLENGE",
                "step": 4,
                "n2_cipher_hex": encrypt_json_hex(
                    session_key, {"N2": n2}
                )
            })

            jawaban = recv_json(conn)

            hasil = decrypt_json_hex(
                session_key, jawaban["response_cipher_hex"]
            )

            if hasil.get("F_N2") != n2[::-1]:
                send_json(conn, {"type": "AUTH_FAIL"})
                print("Autentikasi Alice gagal.")
                return

            send_json(conn, {"type": "AUTH_OK"})

            print("\nAutentikasi Alice berhasil.")
            print("Komunikasi AES dimulai.")

            komunikasi(conn, session_key)

        except Exception as error:
            print("Koneksi Alice gagal:", error)


def listener():
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as server:
        server.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        server.bind((BOB_IP, BOB_PORT))
        server.listen()

        print(f"Bob menunggu koneksi di port {BOB_PORT}.")

        while True:
            conn, addr = server.accept()

            threading.Thread(
                target=layani_alice,
                args=(conn, addr),
                daemon=True
            ).start()


if __name__ == "__main__":
    threading.Thread(
        target=listener, daemon=True
    ).start()

    while True:
        print("\n=== MENU BOB ===")
        print("1. Keluar")

        pilihan = input("Pilih: ")

        if pilihan == "1":
            break
