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
    key = input("Masukkan KA (16 karakter ASCII): ")

    if len(key.encode("ascii")) != 16:
        raise ValueError("KA harus 16 byte ASCII.")

    return key.encode("ascii")


def receive_messages(sock, KS):
    while True:
        try:
            data = recv_json(sock)

            if data.get("type") == "CHAT":
                print("\nCiphertext Hex dari Bob:")
                print(data["cipher_hex"])

                plaintext = decrypt_text_hex(
                    KS, data["cipher_hex"]
                )

                print("Bob:", plaintext)
                print("Alice> ", end="", flush=True)

            elif data.get("type") == "CHAT_QUIT":
                print("\nBob memutuskan koneksi.")
                break

        except Exception as e:
            print("\nKoneksi berakhir:", e)
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kdc", required=True)
    parser.add_argument("--kdc-port", type=int, default=5000)
    parser.add_argument("--bob", required=True)
    parser.add_argument("--bob-port", type=int, default=5001)
    args = parser.parse_args()

    KA = input_key()

    IDA = "Alice"
    IDB = "Bob"
    N1 = secrets.token_hex(8)

    # Langkah 1: Alice meminta session key kepada KDC.
    with socket.create_connection(
        (args.kdc, args.kdc_port)
    ) as sock:

        send_json(sock, {
            "type": "KDC_REQUEST",
            "IDA": IDA,
            "IDB": IDB,
            "N1": N1
        })

        response = recv_json(sock)

    # Langkah 2: Alice membuka bagian yang dienkripsi KA.
    if response.get("type") != "KDC_RESPONSE":
        raise ValueError("Respons KDC tidak valid.")

    bagian = decrypt_json_hex(
        KA, response["alice_part_hex"]
    )

    if (
        bagian["IDA"] != IDA
        or bagian["IDB"] != IDB
        or bagian["N1"] != N1
    ):
        raise ValueError("Identitas atau nonce tidak cocok.")

    KS = bagian["KS"].encode("ascii")

    if len(KS) != 16:
        raise ValueError("Session key tidak valid.")

    print("Langkah 1 dan 2 berhasil.")

    # Langkah 3: Alice meneruskan tiket kepada Bob.
    with socket.create_connection(
        (args.bob, args.bob_port)
    ) as sock:

        send_json(sock, {
            "type": "TICKET",
            "step": 3,
            "ticket_bob_hex": response["ticket_bob_hex"]
        })

        # Langkah 4: Alice menerima E(KS, N2).
        challenge = recv_json(sock)

        if challenge.get("type") != "CHALLENGE":
            raise ValueError("Challenge Bob tidak valid.")

        isi = decrypt_json_hex(
            KS, challenge["n2_cipher_hex"]
        )

        N2 = isi["N2"]

        # f(N2) dalam contoh ini adalah membalik karakter N2.
        jawaban = N2[::-1]

        # Langkah 5: Alice mengirim E(KS, f(N2)).
        send_json(sock, {
            "type": "CHALLENGE_RESPONSE",
            "step": 5,
            "response_cipher_hex": encrypt_json_hex(
                KS, {"F_N2": jawaban}
            )
        })

        status = recv_json(sock)

        if status.get("type") != "AUTH_OK":
            raise ValueError("Autentikasi Alice gagal.")

        print("Langkah 5 berhasil.")
        print("Autentikasi selesai. Chat AES aktif.")

        receiver = threading.Thread(
            target=receive_messages,
            args=(sock, KS),
            daemon=True
        )
        receiver.start()

        while receiver.is_alive():
            try:
                pesan = input("Alice> ")

                if pesan == "/quit":
                    send_json(sock, {"type": "CHAT_QUIT"})
                    break

                pesan.encode("ascii")

                cipher = encrypt_text_hex(KS, pesan)

                print("Ciphertext Hex:", cipher)

                send_json(sock, {
                    "type": "CHAT",
                    "sender": "Alice",
                    "cipher_hex": cipher
                })

            except UnicodeEncodeError:
                print("Pesan harus menggunakan ASCII.")
            except (ConnectionError, OSError):
                break


if __name__ == "__main__":
    main()