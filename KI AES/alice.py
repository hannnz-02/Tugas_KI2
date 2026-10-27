

import socket
import json
import secrets
import threading

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    decrypt_json_hex,
    encrypt_text_hex,
    decrypt_text_hex,
)

# Konfigurasi Alice
KDC_IP = "192.168.43.129"
KDC_PORT = 5000
ALICE_IP = "0.0.0.0"
ALICE_PORT = 5001
BOB_IP = "192.168.43.130"
BOB_PORT = 5001

KA = b"1234567890ABCDEF"


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
                print("\nBob mengakhiri sesi.")
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
            pesan = input("Alice: ")

            if pesan == "/quit":
                send_json(conn, {"type": "CHAT_QUIT"})
                break

            pesan.encode("ascii")

            ciphertext = encrypt_text_hex(
                session_key, pesan
            )

            send_json(conn, {
                "type": "CHAT",
                "sender": "Alice",
                "cipher_hex": ciphertext
            })

            print("Ciphertext Hex:", ciphertext)

        except UnicodeEncodeError:
            print("Gunakan karakter ASCII.")
        except Exception as error:
            print("Koneksi berakhir:", error)
            break


def minta_session_key():
    n1 = secrets.token_hex(8)

    with socket.create_connection(
        (KDC_IP, KDC_PORT)
    ) as conn:
        send_json(conn, {
            "type": "KDC_REQUEST",
            "IDA": "Alice",
            "IDB": "Bob",
            "N1": n1
        })

        response = recv_json(conn)

    if response.get("type") != "KDC_RESPONSE":
        print("KDC menolak permintaan.")
        return None, None

    bagian_alice = decrypt_json_hex(
        KA, response["alice_part_hex"]
    )

    if (
        bagian_alice.get("IDA") != "Alice"
        or bagian_alice.get("IDB") != "Bob"
        or bagian_alice.get("N1") != n1
    ):
        print("Respons KDC tidak valid.")
        return None, None

    session_key = bagian_alice["KS"].encode("ascii")

    print("Session key diterima dari KDC.")
    return session_key, response["ticket_bob_hex"]


def mulai_sesi():
    session_key, tiket = minta_session_key()

    if session_key is None:
        return

    try:
        with socket.create_connection(
            (BOB_IP, BOB_PORT)
        ) as conn:
            send_json(conn, {
                "type": "TICKET",
                "step": 3,
                "initiator": "Alice",
                "ticket_hex": tiket
            })

            challenge = recv_json(conn)

            n2 = decrypt_json_hex(
                session_key,
                challenge["n2_cipher_hex"]
            )["N2"]

            send_json(conn, {
                "type": "CHALLENGE_RESPONSE",
                "step": 5,
                "response_cipher_hex": encrypt_json_hex(
                    session_key,
                    {"F_N2": n2[::-1]}
                )
            })

            status = recv_json(conn)

            if status.get("type") != "AUTH_OK":
                print("Autentikasi gagal.")
                return

            print("Autentikasi Alice-Bob berhasil.")
            print("Komunikasi AES dimulai.")

            komunikasi(conn, session_key)

    except Exception as error:
        print("Gagal memulai sesi:", error)


def listener():
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as server:
        server.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        server.bind((ALICE_IP, ALICE_PORT))
        server.listen()

        print(f"Alice menunggu koneksi di port {ALICE_PORT}.")

        while True:
            conn, addr = server.accept()
            threading.Thread(
                target=layani_koneksi,
                args=(conn, addr),
                daemon=True
            ).start()


def layani_koneksi(conn, addr):
    with conn:
        try:
            tiket = recv_json(conn)
            if tiket.get("type") != "TICKET":
                return

            data_tiket = decrypt_json_hex(
                KA, tiket["ticket_hex"]
            )

            session_key = data_tiket["KS"].encode("ascii")
            n2 = secrets.token_hex(8)

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
                return

            send_json(conn, {"type": "AUTH_OK"})
            komunikasi(conn, session_key)

        except Exception as error:
            print("Koneksi masuk gagal:", error)


if __name__ == "__main__":
    threading.Thread(
        target=listener, daemon=True
    ).start()

    while True:
        print("\n=== MENU ALICE ===")
        print("1. Mulai sesi dengan Bob")
        print("2. Keluar")

        pilihan = input("Pilih: ")

        if pilihan == "1":
            mulai_sesi()
        elif pilihan == "2":
            break
