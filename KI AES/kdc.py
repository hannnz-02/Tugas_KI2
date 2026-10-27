
import argparse
import socket
import threading

from aes_manual import (
    send_json,
    recv_json,
    encrypt_json_hex,
    decrypt_json_hex,
    make_ascii_key
)

LOCK = threading.Lock()

KEYS = {
    "Alice": None,
    "Bob": None
}


def input_key(label):
    while True:
        value = input(
            f"Masukkan {label} (16 karakter ASCII): "
        )

        try:
            key = value.encode("ascii")
        except UnicodeEncodeError:
            print("Kunci harus menggunakan ASCII.")
            continue

        if len(key) == 16:
            return key

        print("Kunci harus tepat 16 byte.")


def handle_client(conn, address):
    with conn:
        try:
            request = recv_json(conn)
            jenis = request.get("type")

            if jenis == "KDC_REQUEST":
                ida = request.get("IDA")
                idb = request.get("IDB")
                n1 = request.get("N1")

                if (
                    ida not in KEYS
                    or idb not in KEYS
                    or ida == idb
                    or not isinstance(n1, str)
                ):
                    send_json(conn, {
                        "type": "ERROR",
                        "message": "Identitas atau nonce tidak valid"
                    })
                    return

                with LOCK:
                    key_initiator = KEYS[ida]
                    key_target = KEYS[idb]

                ks = make_ascii_key()

                # Bagian untuk peminta: E(KA, KS || IDA || IDB || N1)
                bagian_peminta = encrypt_json_hex(
                    key_initiator,
                    {
                        "KS": ks.decode("ascii"),
                        "IDA": ida,
                        "IDB": idb,
                        "N1": n1
                    }
                )

                # Tiket target: E(KB, KS || IDA)
                tiket_target = encrypt_json_hex(
                    key_target,
                    {
                        "KS": ks.decode("ascii"),
                        "IDA": ida
                    }
                )

                send_json(conn, {
                    "type": "KDC_RESPONSE",
                    "step": 2,
                    "alice_part_hex": bagian_peminta,
                    "ticket_bob_hex": tiket_target
                })

                print(
                    f"[KDC] Session baru dibuat: {ida} -> {idb}"
                )

            elif jenis in ("CHANGE_KA", "CHANGE_KB"):
                identity = (
                    "Alice" if jenis == "CHANGE_KA" else "Bob"
                )

                with LOCK:
                    old_key = KEYS[identity]

                update = decrypt_json_hex(
                    old_key, request["update_hex"]
                )

                new_text = update.get("new_key", "")
                new_key = new_text.encode("ascii")

                if len(new_key) != 16:
                    send_json(conn, {
                        "type": "ERROR",
                        "message": "Kunci harus 16 byte ASCII"
                    })
                    return

                with LOCK:
                    KEYS[identity] = new_key

                send_json(conn, {
                    "type": "KEY_CHANGED",
                    "identity": identity
                })

                print(f"[KDC] Kunci {identity} diperbarui.")

            else:
                send_json(conn, {
                    "type": "ERROR",
                    "message": "Jenis permintaan tidak dikenal"
                })

        except Exception as error:
            print("[KDC] Kesalahan:", error)

            try:
                send_json(conn, {
                    "type": "ERROR",
                    "message": "Permintaan gagal"
                })
            except Exception:
                pass


def console_menu():
    while True:
        print("1. Ganti KA")
        print("2. Ganti KB")
        print("3. Kembali menunggu permintaan")

        choice = input("Pilih: ").strip()

        if choice == "1":
            new_key = input_key("KA baru")

            with LOCK:
                KEYS["Alice"] = new_key

            print(
                "KA di KDC berubah. "
                "Alice juga harus memakai KA yang sama."
            )

        elif choice == "2":
            new_key = input_key("KB baru")

            with LOCK:
                KEYS["Bob"] = new_key

            print(
                "KB di KDC berubah. "
                "Bob juga harus memakai KB yang sama."
            )

        elif choice == "3":
            continue

        else:
            print("Pilihan tidak valid.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    KEYS["Alice"] = input_key("KA")
    KEYS["Bob"] = input_key("KB")

    threading.Thread(
        target=console_menu,
        daemon=True
    ).start()

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((args.host, args.port))
        server.listen()

        print(
            f"KDC berjalan pada {args.host}:{args.port}"
        )

        while True:
            conn, address = server.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, address),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()
