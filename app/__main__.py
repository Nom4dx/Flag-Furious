import argparse
import logging
import threading
import webbrowser
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Forensic Hub — local analysis workspace")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if not args.no_browser:

        def open_when_ready():
            import time
            import urllib.request

            for _ in range(120):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{args.port}/api/health", timeout=1).close()
                    webbrowser.open(f"http://127.0.0.1:{args.port}")
                    return
                except OSError:
                    time.sleep(0.5)

        threading.Thread(target=open_when_ready, daemon=True).start()
    uvicorn.run("app.main:app", host="127.0.0.1", port=args.port, workers=1)


if __name__ == "__main__":
    main()
