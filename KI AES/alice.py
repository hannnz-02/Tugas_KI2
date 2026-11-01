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

# KONFIGURASI ALICE
KDC_IP = "192.168.222.1"
KDC_PORT = 5000

ALICE_IP = "192.168.222.129"
ALICE_PORT = 5001

BOB_IP = "192.168.222.130"
BOB_PORT = 5001

KA = b"1234567890ABCDEF"

INPUT_LOCK = threading.Lock()
SEND_LOCK = threading.Lock()
SESSION_LOCK = threading.Lock()
SESSION_ACTIVE = threading.Event()


def safe_send(conn, data):
    with SEND_LOCK:
        send_json(conn, data)


def get_key():
    return KA


def update_key():
    global KA

    while True:
        with INPUT_LOCK:
            new_text = input("Masukkan KA baru (16 ASCII): ")

        try:
            new_key = new_text.encode("ascii")
        except UnicodeEncodeError:
            print("Key harus ASCII.")
            continue

        if len(new_key) != 16:
            print("Key harus 16 byte.")
            continue

        try:
            with socket.create_connection(
                (KDC_IP, KDC_PORT)
            ) as conn:

                safe_send(conn, {
                    "type": "CHANGE_KA",
                    "update_hex": encrypt_json_hex(
                        KA,
                        {"new_key": new_text}
                    )
                })

                response = recv_json(conn)

            if response.get("type") == "KEY_CHANGED":
                KA = new_key
                print("KA berhasil diperbarui di Alice dan KDC.")
            else:
                print("Perubahan KA gagal:", response)

            return

        except Exception as error:
            print("Gagal mengubah KA:", error)
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

                print("\nCiphertext Bob:")
                print(ciphertext)

                print(f"\nBob: {plaintext}")
                print("Alice: ", end="", flush=True)

            elif data.get("type") == "CHAT_QUIT":
                print("\nBob mengakhiri sesi.")
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
                pesan = input("Alice: ")
            if pesan == "/change-key":
                update_key()
                continue

            if pesan == "/quit":
                safe_send(conn, {"type": "CHAT_QUIT"})
                break

            pesan.encode("ascii")

            ciphertext = encrypt_text_hex(
                session_key,
                pesan
            )

            safe_send(conn, {
                "type": "CHAT",
                "sender": "Alice",
                "cipher_hex": ciphertext
            })

            print("\nCiphertext Alice:")
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
            "IDA": "Alice",
            "IDB": "Bob",
            "N1": n1
        })

        response = recv_json(conn)

    if response.get("type") != "KDC_RESPONSE":
        raise ValueError("Respons KDC tidak valid.")

    bagian = decrypt_json_hex(
        KA,
        response["initiator_part_hex"]
    )

    if (
        bagian.get("IDA") != "Alice"
        or bagian.get("IDB") != "Bob"
        or bagian.get("N1") != n1
    ):
        raise ValueError("Respons KDC tidak cocok.")

    session_key = bagian["KS"].encode("ascii")

    if len(session_key) != 16:
        raise ValueError("Session key tidak valid.")

    return session_key, response["ticket_target_hex"]


# ALICE SEBAGAI INITIATOR
def mulai_sesi():

    if not SESSION_LOCK.acquire(blocking=False):
        print("Sesi lain sedang berjalan.")
        return

    SESSION_ACTIVE.set()

    try:
        session_key, tiket = minta_session_key()

        print("Session key diterima dari KDC.")

        with socket.create_connection(
            (BOB_IP, BOB_PORT)
        ) as conn:

            # LANGKAH 3
            send_json(conn, {
                "type": "TICKET",
                "step": 3,
                "initiator": "Alice",
                "ticket_hex": tiket
            })

            # LANGKAH 4
            challenge = recv_json(conn)

            if challenge.get("type") != "CHALLENGE":
                raise ValueError("Challenge tidak valid.")

            n2 = decrypt_json_hex(
                session_key,
                challenge["n2_cipher_hex"]
            )["N2"]

            # LANGKAH 5
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

            print("Autentikasi Alice-Bob berhasil.")
            print("Komunikasi AES dimulai.")

            komunikasi(conn, session_key)

    except Exception as error:
        print("Gagal memulai sesi:", error)

    finally:
        SESSION_ACTIVE.clear()
        SESSION_LOCK.release()

def main():
    while True:
        if SESSION_ACTIVE.is_set():
            time.sleep(0.2)
            continue

        with INPUT_LOCK:
            print("\n=== MENU ALICE ===")
            print("1. Mulai sesi dengan Bob")
            print("2. Ganti KA")
            print("3. Keluar")

            pilihan = input("Pilih: ").strip()

        if pilihan == "1":
            mulai_sesi()

        elif pilihan == "2":
            update_key()

        elif pilihan == "3":
            break

        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
