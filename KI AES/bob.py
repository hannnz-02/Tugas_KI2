
import socket
import threading
import secrets
import time

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    decrypt_json_hex,
    encrypt_text_hex,
    decrypt_text_hex
)

KDC_IP = "192.168.222.1"
KDC_PORT = 5000

BOB_IP = "192.168.222.130"
BOB_PORT = 5001

ALICE_IP = "192.168.222.129"
ALICE_PORT = 5001

KB = b"FEDCBA0987654321"

INPUT_LOCK = threading.Lock()
SEND_LOCK = threading.Lock()
SESSION_LOCK = threading.Lock()
SESSION_ACTIVE = threading.Event()

def safe_send(conn, data):
    with SEND_LOCK:
        send_json(conn, data)
        
def get_key():
    return KB

def update_key():
    global KB

    while True:
        with INPUT_LOCK:
            new_text = input(
                "Masukkan KB baru (16 ASCII): "
            )

        try:
            new_key = new_text.encode("ascii")

        except UnicodeEncodeError:
            print("Key harus menggunakan ASCII.")
            continue

        if len(new_key) != 16:
            print("Key harus tepat 16 byte.")
            continue

        try:
            with socket.create_connection(
                (KDC_IP, KDC_PORT)
            ) as conn:

                safe_send(conn, {
                    "type": "CHANGE_KB",
                    "update_hex": encrypt_json_hex(
                        KB,
                        {"new_key": new_text}
                    )
                })

                response = recv_json(conn)

            if response.get("type") == "KEY_CHANGED":
                KB = new_key

                print(
                    "KB berhasil diperbarui di Bob dan KDC."
                )

            else:
                print(
                    "Perubahan KB gagal:",
                    response
                )

            return

        except Exception as error:
            print("Gagal mengubah KB:", error)
            return

def terima_pesan(conn, session_key):

    while True:
        try:
            data = recv_json(conn)

            if data.get("type") == "CHAT":

                ciphertext = data["cipher_hex"]

                plaintext = decrypt_text_hex(
                    session_key,
                    ciphertext
                )

                print("\nCiphertext Alice:")
                print(ciphertext)

                print(f"\nAlice: {plaintext}")

                print("Bob: ", end="", flush=True)

            elif data.get("type") == "CHAT_QUIT":

                print("\nAlice mengakhiri sesi.")
                break

        except Exception as error:
            print("\nKoneksi berakhir:", error)
            break

def komunikasi(conn, session_key):

    receiver = threading.Thread(
        target=terima_pesan,
        args=(conn, session_key),
        daemon=True
    )

    receiver.start()

    while True:

        try:
            with INPUT_LOCK:
                pesan = input("Bob: ")

            if pesan == "/change-key":

                update_key()
                continue

            if pesan == "/quit":

                safe_send(conn, {
                    "type": "CHAT_QUIT"
                })

                break

            pesan.encode("ascii")

            ciphertext = encrypt_text_hex(
                session_key,
                pesan
            )

            safe_send(conn, {
                "type": "CHAT",
                "sender": "Bob",
                "cipher_hex": ciphertext
            })

            print("\nCiphertext Bob:")
            print(ciphertext)

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
            "IDA": "Bob",
            "IDB": "Alice",
            "N1": n1
        })

        response = recv_json(conn)

    if response.get("type") != "KDC_RESPONSE":
        raise ValueError("Respons KDC tidak valid.")

    bagian = decrypt_json_hex(
        KB,
        response["initiator_part_hex"]
    )

    if (
        bagian.get("IDA") != "Bob"
        or bagian.get("IDB") != "Alice"
        or bagian.get("N1") != n1
    ):
        raise ValueError("Respons KDC tidak cocok.")

    session_key = bagian["KS"].encode("ascii")

    if len(session_key) != 16:
        raise ValueError("Session key tidak valid.")

    return session_key, response["ticket_target_hex"]

# BOB SEBAGAI INITIATOR
def mulai_sesi():
    if not SESSION_LOCK.acquire(blocking=False):
        print("Sesi lain sedang berjalan.")
        return

    SESSION_ACTIVE.set()

    try:
        session_key, tiket = minta_session_key()

        print("Session key diterima dari KDC.")

        with socket.create_connection(
            (ALICE_IP, ALICE_PORT)
        ) as conn:

            send_json(conn, {
                "type": "TICKET",
                "step": 3,
                "initiator": "Bob",
                "ticket_hex": tiket
            })

            challenge = recv_json(conn)

            if challenge.get("type") != "CHALLENGE":
                raise ValueError("Challenge tidak valid.")

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
                raise ValueError("Autentikasi gagal.")

            print("Autentikasi Bob-Alice berhasil.")
            print("Komunikasi AES dimulai.")

            komunikasi(conn, session_key)

    except Exception as error:
        print("Gagal memulai sesi:", error)

    finally:
        SESSION_ACTIVE.clear()
        SESSION_LOCK.release()

def layani_alice(conn, addr):

    try:
        tiket = recv_json(conn)

        if tiket.get("type") != "TICKET":
            return

        data_tiket = decrypt_json_hex(
            KB,
            tiket["ticket_hex"]
        )

        if data_tiket.get("IDA") != "Alice":

            safe_send(conn, {
                "type": "AUTH_FAIL"
            })

            return

        session_key = data_tiket["KS"].encode(
            "ascii"
        )

        if len(session_key) != 16:

            safe_send(conn, {
                "type": "AUTH_FAIL"
            })

            return

        n2 = secrets.token_hex(8)


        safe_send(conn, {
            "type": "CHALLENGE",
            "step": 4,
            "n2_cipher_hex": encrypt_json_hex(
                session_key,
                {"N2": n2}
            )
        })

        jawaban = recv_json(conn)

        if jawaban.get("type") != "CHALLENGE_RESPONSE":

            safe_send(conn, {
                "type": "AUTH_FAIL"
            })

            return

        hasil = decrypt_json_hex(
            session_key,
            jawaban["response_cipher_hex"]
        )

        if hasil.get("F_N2") != n2[::-1]:

            safe_send(conn, {
                "type": "AUTH_FAIL"
            })

            print("Autentikasi Alice gagal.")
            return

        safe_send(conn, {
            "type": "AUTH_OK"
        })

        print("\nAutentikasi Alice-Bob berhasil.")
        print("Komunikasi AES dimulai.")

        komunikasi(conn, session_key)

    except Exception as error:

        print("Koneksi Alice gagal:", error)

def listener():

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind(
            (BOB_IP, BOB_PORT)
        )

        server.listen()

        print(
            f"Bob menunggu koneksi pada port {BOB_PORT}..."
        )

        conn, addr = server.accept()

        with conn:

            print(
                f"Koneksi diterima dari Alice: {addr}"
            )

            layani_alice(conn, addr)

def main():

    while True:

        print("\n=== MENU BOB ===")
        print("1. Mulai menunggu koneksi Alice")
        print("2. Ganti KB")
        print("3. Keluar")

        pilihan = input("Pilih: ").strip()

        if pilihan == "1":

            try:
                listener()

            except Exception as error:

                print(
                    "Kesalahan listener:",
                    error
                )

        elif pilihan == "2":

            update_key()

        elif pilihan == "3":

            print("Bob keluar.")
            break

        else:

            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
