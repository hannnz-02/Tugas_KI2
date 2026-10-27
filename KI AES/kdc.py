import socket
import argparse

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    make_ascii_key
)


def input_key(nama):
    key = input(
        f"Masukkan {nama} (16 karakter ASCII): "
    )

    if len(key.encode("ascii")) != 16:
        raise ValueError("Kunci harus 16 byte ASCII.")

    return key.encode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    KA = input_key("KA untuk Alice")
    KB = input_key("KB untuk Bob")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen()

    print("KDC aktif:", args.host, args.port)

    while True:
        conn, addr = server.accept()

        with conn:
            try:
                request = recv_json(conn)

                if request.get("type") != "KDC_REQUEST":
                    send_json(conn, {
                        "type": "ERROR",
                        "message": "Permintaan tidak valid"
                    })
                    continue

                IDA = request["IDA"]
                IDB = request["IDB"]
                N1 = request["N1"]

                # KDC membuat session key baru.
                KS = make_ascii_key()

                # Langkah 2 bagian untuk Alice.
                bagian_alice = encrypt_json_hex(KA, {
                    "KS": KS.decode("ascii"),
                    "IDA": IDA,
                    "IDB": IDB,
                    "N1": N1
                })

                # Langkah 2 tiket untuk Bob.
                tiket_bob = encrypt_json_hex(KB, {
                    "KS": KS.decode("ascii"),
                    "IDA": IDA
                })

                send_json(conn, {
                    "type": "KDC_RESPONSE",
                    "step": 2,
                    "alice_part_hex": bagian_alice,
                    "ticket_bob_hex": tiket_bob
                })

                print("Langkah 1 diterima dari:", addr)
                print("Langkah 2 selesai. Session key dibuat.")

            except Exception as e:
                print("Kesalahan KDC:", e)

    server.close()


if __name__ == "__main__":
    main()