import socket
import argparse
import secrets
import threading

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    decrypt_json_hex,
    encrypt_text_hex,
    decrypt_text_hex
)


def input_key():
    key = input("Masukkan KB (16 karakter ASCII): ")

    if len(key.encode("ascii")) != 16:
        raise ValueError("KB harus 16 byte ASCII.")

    return key.encode("ascii")


def receive_messages(conn, KS):
    while True:
        try:
            data = recv_json(conn)

            if data.get("type") == "CHAT":
                print("\nCiphertext Hex dari Alice:")
                print(data["cipher_hex"])

                plaintext = decrypt_text_hex(
                    KS, data["cipher_hex"]
                )

                print("Alice:", plaintext)
                print("Bob> ", end="", flush=True)

            elif data.get("type") == "CHAT_QUIT":
                print("\nAlice memutuskan koneksi.")
                break

        except Exception as e:
            print("\nKoneksi berakhir:", e)
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    KB = input_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)

    print("Bob menunggu Alice di", args.host, args.port)

    conn, addr = server.accept()
    print("Alice terhubung:", addr)

    with conn:
        # Langkah 3: Alice meneruskan tiket kepada Bob.
        tiket = recv_json(conn)

        if tiket.get("type") != "TICKET":
            raise ValueError("Tiket tidak valid.")

        isi_tiket = decrypt_json_hex(
            KB, tiket["ticket_bob_hex"]
        )

        KS = isi_tiket["KS"].encode("ascii")
        IDA = isi_tiket["IDA"]

        if len(KS) != 16:
            raise ValueError("Session key tidak valid.")

        print("Langkah 3 berhasil. Tiket dari", IDA)

        # Langkah 4: Bob mengirim E(KS, N2).
        N2 = secrets.token_hex(8)

        send_json(conn, {
            "type": "CHALLENGE",
            "step": 4,
            "n2_cipher_hex": encrypt_json_hex(
                KS, {"N2": N2}
            )
        })

        # Langkah 5: Bob memeriksa E(KS, f(N2)).
        balasan = recv_json(conn)

        if balasan.get("type") != "CHALLENGE_RESPONSE":
            raise ValueError("Balasan langkah 5 tidak valid.")

        hasil = decrypt_json_hex(
            KS, balasan["response_cipher_hex"]
        )

        if hasil.get("F_N2") != N2[::-1]:
            send_json(conn, {
                "type": "AUTH_FAIL",
                "message": "Autentikasi gagal"
            })
            raise ValueError("Respons nonce salah.")

        send_json(conn, {"type": "AUTH_OK"})

        print("Langkah 5 berhasil.")
        print("Autentikasi berhasil. Chat AES aktif.")

        # Terima pesan di thread terpisah supaya Bob
        # tetap dapat mengetik dan mengirim pesan.
        receiver = threading.Thread(
            target=receive_messages,
            args=(conn, KS),
            daemon=True
        )
        receiver.start()

        while receiver.is_alive():
            try:
                pesan = input("Bob> ")

                if pesan == "/quit":
                    send_json(conn, {"type": "CHAT_QUIT"})
                    break

                pesan.encode("ascii")

                cipher = encrypt_text_hex(KS, pesan)

                print("Ciphertext Hex:", cipher)

                send_json(conn, {
                    "type": "CHAT",
                    "sender": "Bob",
                    "cipher_hex": cipher
                })

            except UnicodeEncodeError:
                print("Pesan harus menggunakan ASCII.")
            except (ConnectionError, OSError):
                break

    server.close()


if __name__ == "__main__":
    main()