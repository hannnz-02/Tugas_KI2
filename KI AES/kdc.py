
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
        value = input(f"Masukkan {label} (16 karakter ASCII): ")

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

            # LANGKAH 1 DAN 2: DISTRIBUSI SESSION KEY
            if jenis == "KDC_REQUEST":
                ida = request.get("IDA")
                idb = request.get("IDB")
                n1 = request.get("N1")

                if (
                    ida not in KEYS
                    or idb not in KEYS
                    or ida == idb
                    or not isinstance(n1, str)
                    or not n1
                ):
                    send_json(conn, {
                        "type": "ERROR",
                        "message": "Identitas atau nonce tidak valid"
                    })
                    return

                with LOCK:
                    key_initiator = KEYS[ida]
                    key_target = KEYS[idb]

                if (
                    not isinstance(key_initiator, bytes)
                    or not isinstance(key_target, bytes)
                    or len(key_initiator) != 16
                    or len(key_target) != 16
                ):
                    raise ValueError("Key KDC tidak valid.")

                # Membuat session key baru
                ks = make_ascii_key()

                # Bagian untuk initiator
                bagian_initiator = encrypt_json_hex(
                    key_initiator,
                    {
                        "KS": ks.decode("ascii"),
                        "IDA": ida,
                        "IDB": idb,
                        "N1": n1
                    }
                )

                # Ticket untuk responder
                ticket_target = encrypt_json_hex(
                    key_target,
                    {
                        "KS": ks.decode("ascii"),
                        "IDA": ida
                    }
                )

                send_json(conn, {
                    "type": "KDC_RESPONSE",
                    "step": 2,
                    "initiator_part_hex": bagian_initiator,
                    "ticket_target_hex": ticket_target
                })

                print(f"[KDC] Session key dibuat: {ida} -> {idb}")

            # PERUBAHAN KA ATAU KB
            elif jenis in ("CHANGE_KA", "CHANGE_KB"):

                identity = (
                    "Alice" if jenis == "CHANGE_KA" else "Bob"
                )

                with LOCK:
                    old_key = KEYS[identity]

                update = decrypt_json_hex(
                    old_key,
                    request["update_hex"]
                )

                new_text = update.get("new_key")

                if not isinstance(new_text, str):
                    raise ValueError("Key harus berupa teks.")

                new_key = new_text.encode("ascii")

                if len(new_key) != 16:
                    raise ValueError("Key harus 16 byte ASCII.")

                with LOCK:
                    if KEYS[identity] != old_key:
                        raise ValueError("Key berubah saat proses berlangsung.")

                    KEYS[identity] = new_key

                send_json(conn, {
                    "type": "KEY_CHANGED",
                    "identity": identity
                })

                print(f"[KDC] Key {identity} berhasil diperbarui.")

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
                    "message": str(error)
                })
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    KEYS["Alice"] = input_key("KA untuk Alice")
    KEYS["Bob"] = input_key("KB untuk Bob")

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((args.host, args.port))
        server.listen()

        print(f"KDC berjalan pada {args.host}:{args.port}")

        while True:
            conn, address = server.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, address),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()
