
import argparse, email, json, logging, socket, threading, time

logger = logging.getLogger("my_logger")


def setup_logger():
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler("HW4__CLIENT__GROUP_2.log", mode='w')
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s - %(threadName)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def client_load(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info("Connecting to {} @ {}".format(host, port))
    client_socket.connect((host, port))

    receive_thread = threading.Thread(target=client_receive, args=(client_socket,))
    receive_thread.start()

    send_thread = threading.Thread(target=client_send, args=(client_socket, host,))
    send_thread.start()


def client_receive(client_socket):

    while True:
        try:
            data = client_socket.recv(1024)
            headers, body = parse_http_response(data)
            logger.info('Response status: %s'%(headers.get("status")))

            logger.info('Status: %s'% headers.get("status"))
            logger.info('Data: %s'%body)
        except Exception as e:
            logger.error(e)
            client_socket.close()
            logger.info("Socket Closed")
            break


def client_send(client_socket, host):
    message = create_request_payload(host, {f"request_type": "JOIN"})
    client_socket.send(message)
    # logger.info(f"Sent to server: {message}")

    while True:
        try:
            time.sleep(2)
            amount = int(input("Bid amount: ").strip())
            message = create_request_payload(
                host, {"request_type": "BID", "bid_amount": f"{amount}"}
            )
            print(message)
            logger.info(f"Sent to server: {message}")
            client_socket.send(message)

        except Exception as e:
            logger.error(e)
            logger.error("Invalid input: must be an integer. Enter amount:")


def parse_http_response(response: bytes):
    response = response.decode()
    headers, body = response.split("\r\n\r\n", 1)
    status, headers = headers.split("\r\n", 1)

    res = {
        "status": " ".join(status.split(" ")[1:]),
        "http_version": status.split(" ")[0],
    }

    message = email.message_from_string(headers)
    res = {**res, **dict(message.items())}
    return res, json.loads(body)


def create_request_payload(URL: str, payload: dict) -> bytes:
    request = (
        f"POST / HTTP/1.1\r\nHost: {URL}\r\nContent-Type: application/json\r\n\r\n"
    )
    request += json.dumps(payload)
    return request.encode()


if __name__ == "__main__":
    setup_logger()
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--host", action="store", help="server mame")
    parser.add_argument("-p", "--port", type=int, help="server port")

    args = parser.parse_args()
    client_load(args.host, args.port)
