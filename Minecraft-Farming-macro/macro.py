import random
import threading
import time
import keyboard
import pydirectinput

HOLD_KEY          = "w"
STRAFE_KEY        = "d"
TOGGLE_KEY        = "f7"
TOGGLE_STATE      = "f8"
QUIT_KEY          = "f9"
S_key_1           = "f10"
S_key_2           = "f12"
SEQUENCE_START_KEY = "delete"

active  = False   # play / pause
strafe  = False   # w only vs w + d
running = True

_key_lock = threading.Lock()
_seq_lock = threading.Lock()


def sequence():
    if not _seq_lock.acquire(blocking=False):
        print("Sequence already running — ignored")
        return
    try:
        print(f"Sequence started: {S_key_1} → {S_key_2}")

        pydirectinput.press(S_key_1)
        delay = random.uniform(0.5, 1.5)
        print(f"  [{S_key_1}] pressed  (waiting {delay:.2f}s)")
        time.sleep(delay)

        pydirectinput.press(S_key_2)
        print(f"  [{S_key_2}] pressed")
        print("Sequence complete")
    finally:
        _seq_lock.release()


def hold_loop():
    while running:
        with _key_lock:
            if active:
                keyboard.press(HOLD_KEY)
                if strafe:
                    keyboard.press(STRAFE_KEY)
        time.sleep(0.03)


def toggleState():
    global active
    active = not active
    with _key_lock:
        if not active:
            keyboard.release(STRAFE_KEY)
            keyboard.release(HOLD_KEY)
    mode = f"[{HOLD_KEY}+{STRAFE_KEY}]" if strafe else f"[{HOLD_KEY}]"
    print(f"State: {'PLAY ' + mode if active else 'PAUSED'}")


def toggleKey():
    global strafe
    with _key_lock:
        strafe = not strafe
        if active and not strafe:
            keyboard.release(STRAFE_KEY)
    print(f"Mode: {'w+d' if strafe else 'w only'}  |  {'PLAY' if active else 'PAUSED'}")


def main():
    global running

    keyboard.add_hotkey(TOGGLE_KEY,        toggleKey)
    keyboard.add_hotkey(TOGGLE_STATE,      toggleState)
    keyboard.add_hotkey(SEQUENCE_START_KEY,
                        lambda: threading.Thread(target=sequence, daemon=True).start())

    threading.Thread(target=hold_loop, daemon=True).start()

    print("Ready — F7: w / w+d  |  F8: play/pause  |  Delete: sequence  |  F9: quit")
    keyboard.wait(QUIT_KEY)

    running = False
    with _key_lock:
        keyboard.release(STRAFE_KEY)
        keyboard.release(HOLD_KEY)


if __name__ == "__main__":
    main()
