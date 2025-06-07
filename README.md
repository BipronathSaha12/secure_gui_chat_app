# GUI-Based Encrypted Chat Application

A secure, real-time chat application with GUI built using Python, Tkinter, and socket programming. It supports multiple clients, message encryption (RSA), timestamps, emojis, and file transfer (can be extended).

---

## Features

- Real-time sending and receiving of messages
- User-friendly GUI with scrollable chat history
- Username login prompt on startup
- Message timestamps
- RSA-based public-key encryption for secure communication
- Multi-client support on the server side
- Graceful disconnect handling
- Emoji support (depends on OS and Tkinter font support)
- Easily extendable for file transfer and additional features

---

## Project Structure

```

gui\_chat\_app/
│
├── server.py           # Server-side application with multi-client support and encryption
├── client.py           # Client-side GUI application with encryption and chat interface
├── README.md           # This documentation file
└── requirements.txt    # Required Python packages (optional)

````

---

## Requirements

- Python 3.8+
- `pycryptodome` for RSA encryption  
  Install via pip:

```bash
pip install pycryptodome
````

---

## How to Run

1. **Start the Server:**

```bash
python server.py
```

You should see a message like:

```
[STARTED] Server listening on 0.0.0.0:12345
```

2. **Start Client(s):**

In a new terminal window, run:

```bash
python client.py
```

* A popup will ask for your username. Enter it and press OK.
* The main chat window appears.
* Type messages and press Enter or click Send.
* Messages from other connected clients appear in real-time with timestamps.

---

## Usage Notes

* The client app exchanges RSA public keys with the server on connect for secure encrypted communication.
* Messages are sent as JSON strings with username and timestamp fields.
* The chat GUI is scrollable and prevents editing of chat history.
* The client gracefully handles disconnections.
* Emoji support depends on your OS and font support in Tkinter.

---

## Future Improvements

* Add file transfer functionality with encryption
* Improve UI design and responsiveness
* Add user authentication and password support
* Persist chat history to a database or local file
* Add typing indicators and read receipts
* Support group chats and private messaging
* Implement end-to-end encryption for privacy

---

## License

This project is open-source and free to use for educational and personal projects.

---

**Enjoy chatting securely! 🔐💬**

