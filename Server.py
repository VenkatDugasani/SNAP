import argparse, email, json, logging, socket, threading, time

logger = logging.getLogger("my_logger")

STATUS = {
    'request_type': 'STATUS',
    'status': 'CLOSED',
    'highest_bid': None,
    'highest_bidder': None,
    'chant': 0,
    'n_clients': 0,
    'next_auction': None
}
MIN_BID = None
CLIENTS = {}


def setup_logger():
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler("HW4__SERVER__GROUP_2.log", mode='w')
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(threadName)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def chant(auction_obj):
    global STATUS
    while True:
        ct = STATUS['chant']
        if ct < 3:
            last_bid = STATUS['highest_bid']
            time.sleep(10)
            new_bid = STATUS['highest_bid']
            if last_bid == new_bid:
                STATUS['chant'] += 1
                auction_obj.broadcast_status()
        else:
            break
    auction_obj.close()


def countdown(auction_obj):
    while True:
        if time.time() >= STATUS['next_auction']:
            if STATUS['status'] == 'CLOSED':
                logger.info("Auction started.")
                STATUS['status'] = 'OPEN'
                auction_obj.broadcast_status()
                break
        time.sleep(1)


def bind_to_local(tcp_socket):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()

    tcp_socket.bind((hostname, 0))
    port = tcp_socket.getsockname()[1]
    logger.info(f"accepting at host {hostname} @ port {port}")
    tcp_socket.listen()


def auction_server():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_to_local(tcp_socket)
    start_auction(tcp_socket)


class Auction:
    def __init__(self):
        pass

    def broadcast_status(self):
        global CLIENTS
        global STATUS

        logger.info('Broadcasting to %s clients: %s' % (len(CLIENTS), STATUS))

        for c in CLIENTS:
            message = create_response_payload("200 OK", STATUS)
            CLIENTS[c].send(message)

    def join_auction(self, client):
        global CLIENTS
        addr = '%s:%s' % (client.getpeername()[0], client.getpeername()[1])

        if addr not in CLIENTS:
            CLIENTS[addr] = client
            STATUS['n_clients'] = len(CLIENTS)
            self.broadcast_status()

    def bid_auction(self, data, client):
        global STATUS
        global MIN_BID

        if STATUS['status'] == 'CLOSED':
            self.raise_400(client, 'Auction is closed')
            return None
        else:
            try:
                bid_amount = int(data.get('bid_amount'))
            except Exception as e:
                self.raise_400(client, 'Invalid bid amount')
                return None
            else:
                if bid_amount >= MIN_BID:
                    if STATUS['highest_bid'] == None:
                        STATUS['highest_bid'] = bid_amount
                        STATUS['highest_bidder'] = client.getpeername()[0]
                        self.bid_ack(client, 'ACCEPTED')
                        self.broadcast_status()
                        chant_thread = threading.Thread(target=chant, args=(self,))
                        chant_thread.start()
                    elif STATUS['highest_bid'] < bid_amount:
                        STATUS['highest_bid'] = bid_amount
                        STATUS['highest_bidder'] = client.getpeername()[0]
                        self.bid_ack(client, 'ACCEPTED')
                        self.broadcast_status()
                    else:
                        self.bid_ack(client, 'REJECTED')
                else:
                    self.bid_ack(client, 'REJECTED')

    def request_handler(self, metadata, body, client):
        logger.info('Incoming request from %s' % client.getpeername()[0])
        logger.info('Request type: %s' % body.get('request_type'))
        http_request_type = metadata.get('http_request_type')
        http_version = metadata.get('http_version')
        if http_request_type != 'POST' or http_version != 'HTTP/1.1':
            self.raise_400(client, 'Invalid type or http version')
            return None

        request_type = body.get('request_type')
        if request_type not in ['JOIN', 'BID']:
            self.raise_400(client, 'Invalid request_type')
            return None

        if request_type == 'JOIN':
            self.join_auction(client)
        else:
            self.bid_auction(body, client)

    def bid_ack(self, client, m):
        message = create_response_payload('200 OK', {'message': m})
        client.send(message)

    def close(self):
        global CLIENTS
        global STATUS

        STATUS['status'] = 'CLOSED'

        logger.info('Broadcasting close to %s clients' % len(CLIENTS))
        logger.info('SOLD!')
        logger.info('Highest bid: %s' % STATUS.get('highest_bid'))
        logger.info('Highest bidder: %s' % STATUS.get('highest_bidder'))

        for c in CLIENTS:
            kwargs = {
                'request_type': 'CLOSE',
                'highest_bid': STATUS['highest_bid'],
                'highest_bidder': STATUS['highest_bidder']
            }
            message = create_response_payload("200 OK", kwargs)
            CLIENTS[c].send(message)

    def raise_400(self, client, m):
        message = create_response_payload('400 Bad Request', {'message': m})
        client.send(message)


def process_client(client, auction_obj):
    while True:
        try:
            data = client.recv(1024)
            metadata, body = parse_http_request(data)
            if not metadata or not body:
                auction_obj.raise_400(client, 'Invalid response')
                break
            auction_obj.request_handler(metadata, body, client)
        except BrokenPipeError as e:
            pass
        except Exception as e:
            logger.error(e)


def start_auction(tcp_socket):
    auction_obj = Auction()

    cooldown_thread = threading.Thread(target=countdown, args=(auction_obj,))
    cooldown_thread.start()

    while True:
        client, address = tcp_socket.accept()
        logger.info("Connection from: %s:%s" % (address[0], address[1]))

        thread = threading.Thread(target=process_client, args=(client, auction_obj,))
        thread.start()


def parse_http_response(response: bytes) -> tuple:
    response = response.decode()
    try:
        headers, body = response.split("\r\n\r\n", 1)
        status, headers = headers.split("\r\n", 1)
        print(response)

        meta = {
            "status": " ".join(status.split(" ")[1:]),
            "http_version": status.split(" ")[0],
        }

        message = email.message_from_string(headers)
        meta = {**meta, **dict(message.items())}
        return meta, json.loads(body)
    except Exception as e:
        logger.error(e)
        return None, None


def parse_http_request(request: bytes):
    if request:
        request = request.decode()
        headers, body = request.split("\r\n\r\n", 1)
        status, headers = headers.split("\r\n", 1)

        res = {"http_request_type": status.split(" ")[0], "http_version": status.split(" ")[2]}

        message = email.message_from_string(headers)
        res = {**res, **dict(message.items())}
        return res, json.loads(body)
    else:
        return None, None


def create_request_payload(URL: str, payload: dict) -> bytes:
    request = (
        f"POST / HTTP/1.1\r\nHost: {URL}\r\nContent-Type: application/json\r\n\r\n"
    )
    request += json.dumps(payload)
    return request.encode()


def create_response_payload(status_code, payload):
    response = f"HTTP/1.1 {status_code}\r\nContent-Type: application/json\r\n\r\n"
    response += json.dumps(payload)
    return response.encode()


if __name__ == "__main__":
    setup_logger()
    parser = argparse.ArgumentParser()

    parser.add_argument("-m", "--minbid", type=int, help="Minimum bid amount")
    parser.add_argument("-t", "--time", type=int, help="Auction start time")

    args = parser.parse_args()
    MIN_BID = args.minbid
    STATUS['next_auction'] = args.time
    auction_server()
