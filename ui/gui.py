"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import gc
import os
import time
import threading
import tkinter as tk
from tkinter import ttk
from config import VERSION
from tkinter import filedialog as fd
from pathlib import Path
from cuvex.card_helper import process_card
from cuvex.exceptions import *
from cuvex.crypto_helper import decrypt_card
from cuvex.classes import *
from cuvex.utils import clean_bytearray, convert_str_to_code_points
import ui.widget_consts as wcn
import ui.texts as txt
from ui.file_helper import read_binary_file
from ui.connection import check_connection
from tkinter import simpledialog
from tkinter import messagebox
import tkinter.scrolledtext as scrolledtext
from config import ASSETS_DIR

WINDOW_WIDTH = 800
WINDOW_HEIGHT = 450
ROOT_WINDOW = None
IPADX = 5
IPADY = 5
PADX = 5
PADY = 5
WIDGETS = {}
CARD_FILE_PATH = None
TIME_COUNTER = 120 # seconds
EXTEND_COUNTER = 0
RUN_TIMER = False
CARDS_CACHE = {}
DEFAULT_WAIT_TIME = 5 * 60 # 5 minutes

## SECURE!!!
CARD_DATA = None
CARD_PLAIN_CONTENT = None

def clean_vars():
    global CARD_FILE_PATH
    global CARD_DATA
    global CARD_PLAIN_CONTENT
    global TIME_COUNTER
    global EXTEND_COUNTER

    # Secure
    if CARD_DATA:
        CARD_DATA.reset_content()
    CARD_DATA = None
    if CARD_PLAIN_CONTENT:
        CARD_PLAIN_CONTENT.reset_content()
    CARD_PLAIN_CONTENT = None
    del CARD_DATA
    del CARD_PLAIN_CONTENT
    del CARD_FILE_PATH
    del TIME_COUNTER
    del EXTEND_COUNTER
    gc.collect()

def check_internet():
    check = True
    while check:
        check = check_connection()
        if check:
            response = messagebox.askokcancel(title=txt.CHECK_INTERNET_CONNECTION, 
                                   message=txt.INTERNET_CONN_MSG)
            if not response:
                quit_app()
                return check
    return check

def quit_app():
    clean_vars()
    ROOT_WINDOW.quit()

def define_styles():
    main_styles = ttk.Style()
    main_styles.theme_use("clam")
    main_styles.configure('TLabel', 
                          foreground=wcn.PRIMARY_BUTTONS_BG_COLOR,
                          background=wcn.WINDOW_BACKGROUND_COLOR)
    main_styles.configure('TFrame', 
                          background=wcn.WINDOW_BACKGROUND_COLOR)
    main_styles.configure('cnt.TFrame', 
                          background=wcn.WINDOW_BACKGROUND_COLOR,
                          highlightbackground="red",
                          borderwidth=2, 
                          relief='solid', 
                          labelmargins=2)
    main_styles.configure('TButton', 
                          foreground=wcn.WINDOW_BACKGROUND_COLOR,
                          background=wcn.PRIMARY_BUTTONS_BG_COLOR)
    main_styles.map('TButton', 
                    foreground=[('pressed', wcn.WINDOW_BACKGROUND_COLOR), 
                                ('active', wcn.WINDOW_BACKGROUND_COLOR)],
                    background=[('pressed', '!disabled', 
                                 wcn.SECONDARY_BUTTONS_BG_COLOR), 
                                 ('active', wcn.CLICKED_BUTTON_COLOR)])
    WIDGETS[wcn.STL_STYLES] = main_styles

def open_images():
    WIDGETS[wcn.IMG_MAIN_LOGO] = tk.PhotoImage(
        file=os.path.join(ASSETS_DIR, 'logotipo_cuvex_claro.png'))

def reset_variables():
    global CARD_FILE_PATH
    global CARD_DATA
    global CARD_PLAIN_CONTENT
    global TIME_COUNTER
    global EXTEND_COUNTER
    CARD_FILE_PATH = None
    TIME_COUNTER = 120
    EXTEND_COUNTER = 0
    # Secure
    if CARD_DATA:
        CARD_DATA.reset_content()
    CARD_DATA = None
    if CARD_PLAIN_CONTENT:
        CARD_PLAIN_CONTENT.reset_content()
    CARD_PLAIN_CONTENT = None
    gc.collect()

def begin():
    if check_internet():
        return

    hide_frame_welcome()
    show_frame_open_file()

def create_welcome_frame(parent):
    frame = ttk.Frame(parent)

    lbl_wf_title = ttk.Label(frame, 
                     text=txt.WELCOME_TITLE,
                     font=wcn.TITLE_FONT)
    lbl_wf_title.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_wf_logo = ttk.Label(frame, image=WIDGETS[wcn.IMG_MAIN_LOGO])
    lbl_wf_logo.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY+35)

    lbl_wf_warn_conn = ttk.Label(frame, 
                wraplength=550, 
                justify='left', 
                text=txt.INTERNET_NOTICE)
    lbl_wf_warn_conn.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_wf_warn_verify = ttk.Label(frame, 
                wraplength=550, 
                justify='left', 
                text=txt.VERIFICATION_NOTICE)
    lbl_wf_warn_verify.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    btn1 = ttk.Button(frame, text=txt.OK, command=begin)
    btn1.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_wf_ver = ttk.Label(frame, 
                text='v'+VERSION,
                font=wcn.VERSION_FONT)
    lbl_wf_ver.pack(side='bottom', anchor='center', 
                    ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    WIDGETS[wcn.FRAME_WELCOME] = frame
    WIDGETS[wcn.FRW_TITLE] = lbl_wf_title
    WIDGETS[wcn.FRW_CONNECTION_WARN] = lbl_wf_warn_conn
    WIDGETS[wcn.FRW_VERIFY_WARN] = lbl_wf_warn_verify
    WIDGETS[wcn.FRW_VERSION_LBL] = lbl_wf_ver
    WIDGETS[wcn.FRW_OK_BUTTON] = btn1

    return frame

def show_frame_welcome():
    WIDGETS[wcn.FRAME_WELCOME].pack(expand=1, fill=tk.BOTH, 
                                    ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

def hide_frame_welcome():
    WIDGETS[wcn.FRAME_WELCOME].pack_forget()

def create_open_card_frame(parent):
    frame = ttk.Frame(parent)

    title = ttk.Label(frame, 
                     text=txt.OPEN_CARD_TITLE,
                     font=wcn.TITLE_FONT)
    title.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)


    lbl_instructions = ttk.Label(frame, 
                wraplength=550, 
                justify='left', 
                text=txt.OPEN_INSTRUCIONS)
    lbl_instructions.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    btn_proceed = ttk.Button(frame, text=txt.OK, command=open_card_file)
    btn_proceed.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    WIDGETS[wcn.FRAME_OPEN] = frame
    WIDGETS[wcn.FRO_TITLE] = title
    WIDGETS[wcn.FRO_INSTRUCTIONS] = lbl_instructions
    WIDGETS[wcn.FRO_BTN] = btn_proceed

    return frame

def show_frame_open_file():
    WIDGETS[wcn.FRAME_OPEN].pack(expand=1, fill=tk.BOTH, 
                                 ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

def hide_frame_open_file():
    WIDGETS[wcn.FRAME_OPEN].pack_forget()

def open_card_file():
    global CARD_DATA

    if check_internet():
        return

    home = Path.home()
    filename = fd.askopenfilename(
        title=txt.SELECT_CARD_FILE,
        multiple=False,
        initialdir=home,
        filetypes=((txt.BIN_FILES, '*.bin'),))
    global CARD_FILE_PATH
    CARD_FILE_PATH = filename

    if not filename:
        quit_app()
        return

    try:
        bin_content = read_binary_file(filename)
        CARD_DATA = process_card(bin_content)
        clean_bytearray(bin_content)
        del bin_content
    except EmptyCardException as e1:
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.EMPTY_CARD_MSG)
        quit_app()
        return
    except BadFormatContentException as e2:
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.BAD_FORMAT_CARD_MSG)
        quit_app()
        return
    except Exception as e3:
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.UNKNOWN_ERROR_MSG)
        quit_app()
        return

    if not CARD_DATA:
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.IMPOSSIBLE_PROCESS_CARD)
        quit_app()
        return

    if not (CARD_DATA.version.major >= 1 and CARD_DATA.version.minor >= 1):
        messagebox.showerror(title=txt.ERROR_TITLE, 
                             message=txt.VERSION_NOT_SUPPORTED_MSG.format(CARD_DATA.version.full_version))
        quit_app()
        return
    
    if not CARD_DATA.card_hash in CARDS_CACHE:
        CARDS_CACHE[CARD_DATA.card_hash] = {
            'attempts': 0,
            'since': int(time.time())
        }

    hide_frame_open_file()
    show_frame_card_info()

def remove_from_cache(card_hash: str):
    try:
        del CARDS_CACHE[card_hash]
    except Exception:
        pass

def update_attempts(card_hash: str):
    if not card_hash in CARDS_CACHE:
        CARDS_CACHE[card_hash] = {
            'attempts': 0,
            'since': int(time.time())
        }

    CARDS_CACHE[card_hash]['attempts'] = CARDS_CACHE[card_hash]['attempts'] + 1
    CARDS_CACHE[card_hash]['since'] = int(time.time())

def get_attempts_from_cache(card_hash: str):
    if card_hash in CARDS_CACHE:
        return CARDS_CACHE[card_hash]['attempts']
    return 0

def get_last_attempt(card_hash: str):
    if card_hash in CARDS_CACHE:
        return CARDS_CACHE[card_hash]['since']
    return None

def reset_cache_entry(card_hash: str):
    if not card_hash in CARDS_CACHE:
        CARDS_CACHE[card_hash] = {
            'attempts': 0,
            'since': int(time.time())
        }

    CARDS_CACHE[card_hash]['attempts'] = 0
    CARDS_CACHE[card_hash]['since'] = int(time.time())

def proceed_to_input_passwords():
    if check_internet():
        return
    
    time_waited = int(time.time()) - get_last_attempt(CARD_DATA.card_hash)
    if get_attempts_from_cache(CARD_DATA.card_hash) >= 5 and time_waited > DEFAULT_WAIT_TIME:
        reset_cache_entry(CARD_DATA.card_hash)
    elif get_attempts_from_cache(CARD_DATA.card_hash) >= 5 and time_waited <= DEFAULT_WAIT_TIME:
        mins,secs = divmod((DEFAULT_WAIT_TIME - time_waited),60)
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.WAIT_TO_TRY_AGAIN.format(mins, secs))
        quit_app()
        return

    passwords = []
    counter = 0
    global RUN_TIMER
    global CARD_PLAIN_CONTENT

    def _inner_clean_psws():
        if passwords:
            for bp in passwords:
                for x in range(len(bp)):
                    bp[x] = 0

    while counter < CARD_DATA.signs.required:

        try:
            passwords.append(convert_str_to_code_points(simpledialog.askstring(txt.INPUT_PASSWORD_TITLE, 
                                            txt.INPUT_PASSWORD_PROMPT
                                            .format(counter + 1, CARD_DATA.signs.required), 
                                            show='*')))
            counter += 1
        except Exception:
            _inner_clean_psws()
            quit_app()
            return
        
    try:
        CARD_PLAIN_CONTENT = decrypt_card(passwords, CARD_DATA)
    except CardVersionNotSupportedException as e1:
        messagebox.showerror(title=txt.ERROR_TITLE, 
                             message=txt.VERSION_NOT_SUPPORTED_MSG.format(CARD_DATA.version.full_version))
        remove_from_cache(CARD_DATA.card_hash)
        _inner_clean_psws()
        quit_app()
        return
    except FewerPasswordsThanRequiredException as e2:
        messagebox.showerror(title=txt.ERROR_TITLE, 
                             message=txt.FEWER_PASSWORD_THAN_REQUIRED)
        remove_from_cache(CARD_DATA.card_hash)
        _inner_clean_psws()
        quit_app()
        return
    except Exception:
        messagebox.showerror(title=txt.ERROR_TITLE, message=txt.UNKNOWN_ERROR_MSG)
        remove_from_cache(CARD_DATA.card_hash)
        _inner_clean_psws()
        quit_app()
        return

    if not CARD_PLAIN_CONTENT or not CARD_PLAIN_CONTENT.raw_content:
        update_attempts(CARD_DATA.card_hash)
        attempts = get_attempts_from_cache(CARD_DATA.card_hash)
        if attempts >= 5:
            messagebox.showerror(title=txt.ERROR_TITLE, 
                                 message=txt.FAILED_DECRYPTION_WAIT)
            _inner_clean_psws()
            quit_app()
            return
        else: 
            messagebox.showerror(title=txt.ERROR_TITLE, 
                                 message=txt.FAILED_DECRYPTION_RETRY.format(5 - attempts))
            _inner_clean_psws()
            quit_app()
            return

    remove_from_cache(CARD_DATA.card_hash)
    _inner_clean_psws()
    hide_frame_card_info()
    show_frame_card_content()
    RUN_TIMER = True
    threading.Thread(target=init_timer, daemon=True).start()

def create_card_info_frame(parent):
    frame = ttk.Frame(parent)

    title = ttk.Label(frame, 
                     text=txt.CARD_INFO_TITLE,
                     font=wcn.TITLE_FONT)
    title.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_alias = ttk.Label(frame,
                text='')
    lbl_alias.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_signers = ttk.Label(frame,
                text='')
    lbl_signers.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_required = ttk.Label(frame,
                text='')
    lbl_required.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_version = ttk.Label(frame,
                text='')
    lbl_version.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    btn_proceed = ttk.Button(frame, text=txt.PROCEED, 
                             command=proceed_to_input_passwords)
    btn_proceed.pack(side=tk.RIGHT, anchor=tk.SE, expand=True, 
                     ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)


    WIDGETS[wcn.FRAME_CARD_INFO] = frame
    WIDGETS[wcn.FRCI_TITLE] = title
    WIDGETS[wcn.FRCI_ALIAS] = lbl_alias
    WIDGETS[wcn.FRCI_SIGNERS] = lbl_signers
    WIDGETS[wcn.FRCI_REQUIRED] = lbl_required
    WIDGETS[wcn.FRCI_VERSION] = lbl_version
    WIDGETS[wcn.FRCI_BTN] = btn_proceed

    return frame

def show_frame_card_info():
    text_total_signers = txt.SIGNERS_PLURAL.format(CARD_DATA.signs.total)
    if CARD_DATA.signs.total == 1:
        text_total_signers = txt.SIGNERS_SINGULAR
    
    text_required_signs = txt.REQUIRED_PASSWORD_PLURAL.format(CARD_DATA.signs.required)
    if CARD_DATA.signs.required == 1:
        text_required_signs = txt.REQUIRED_PASSWORD_SINGULAR
    
    WIDGETS[wcn.FRCI_ALIAS].config(text=txt.CARD_ALIAS.format(CARD_DATA.alias_str))
    WIDGETS[wcn.FRCI_SIGNERS].config(text=text_total_signers)
    WIDGETS[wcn.FRCI_REQUIRED].config(text=text_required_signs)
    WIDGETS[wcn.FRCI_VERSION].config(text=txt.CARD_VERSION.format(CARD_DATA.version.full_version))
    WIDGETS[wcn.FRAME_CARD_INFO].pack(expand=1, fill=tk.BOTH, ipadx=IPADX, 
                                      ipady=IPADY, padx=PADX, pady=PADY)

def hide_frame_card_info():
    WIDGETS[wcn.FRAME_CARD_INFO].pack_forget()

def extend_time():
    global EXTEND_COUNTER
    global TIME_COUNTER

    if EXTEND_COUNTER < 3:
        TIME_COUNTER += 60
        EXTEND_COUNTER += 1
    else:
        WIDGETS[wcn.FRCC_BTN_ADD_TIME].pack_forget()

def finalize_viewing():
    global RUN_TIMER
    RUN_TIMER = False
    quit_app()

def init_timer():
    global TIME_COUNTER

    while TIME_COUNTER > -1 and RUN_TIMER:
        mins,secs = divmod(TIME_COUNTER,60)
        WIDGETS[wcn.FRCC_TIME].config(text=txt.REMAINING_TIME.format(mins, secs))
        ROOT_WINDOW.update()
        time.sleep(1)
        TIME_COUNTER = TIME_COUNTER - 1

    reset_variables()
    hide_frame_card_content()

    if RUN_TIMER:
        show_frame_end()
    else:
        quit_app()

def create_card_content_frame(parent):
    frame = ttk.Frame(parent)

    title = ttk.Label(frame, 
                     text=txt.CARD_CONTENT_TITLE,
                     font=wcn.TITLE_FONT)
    title.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_instructions = ttk.Label(frame,
                                 wraplength=550,
                                 justify='left', 
                                 text=txt.SHOW_CARD_CONTENT_INSTRUCTIONS)
    lbl_instructions.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_time = ttk.Label(frame,
                text='',
                font=wcn.TIME_REMAINING_FONT)
    lbl_time.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    lbl_content = scrolledtext.ScrolledText(frame, bg=wcn.WINDOW_BACKGROUND_COLOR,
                                    fg=wcn.PRIMARY_BUTTONS_BG_COLOR)
    lbl_content['font'] = ('Helvetica', '12', 'bold italic')
    lbl_content.place(height=200, width=650, x=75, y=170)
    lbl_content.bind('<Control-v>', lambda _:'break')
    lbl_content.bind('<Control-c>', lambda _:'break')
    lbl_content.bind('<BackSpace>', lambda _:'break')

    btn_add_time = ttk.Button(frame, text=txt.EXTEND_TIME, 
                             command=extend_time)
    btn_add_time.pack(side=tk.LEFT, anchor=tk.SW, 
                      ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    btn_finalize = ttk.Button(frame, text=txt.FINALIZE_VIEWING, 
                             command=finalize_viewing)
    btn_finalize.pack(side=tk.RIGHT, anchor=tk.SE, 
                      ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    WIDGETS[wcn.FRAME_CARD_CONTENT] = frame
    WIDGETS[wcn.FRCC_TITLE] = title
    WIDGETS[wcn.FRCC_INSTRUCTIONS] = lbl_instructions
    WIDGETS[wcn.FRCC_TIME] = lbl_time
    WIDGETS[wcn.FRCC_CONTENT] = lbl_content
    WIDGETS[wcn.FRCC_BTN_ADD_TIME] = btn_add_time
    WIDGETS[wcn.FRCC_BTN_FINALIZE] = btn_finalize

    return frame

def show_frame_card_content():
    WIDGETS[wcn.FRAME_CARD_CONTENT].pack(expand=1, fill=tk.BOTH, ipadx=IPADX, 
                                      ipady=IPADY, padx=PADX, pady=PADY)

    WIDGETS[wcn.FRCC_CONTENT].insert(tk.END, CARD_PLAIN_CONTENT.content)

def hide_frame_card_content():
    WIDGETS[wcn.FRAME_CARD_CONTENT].pack_forget()

def create_end_frame(parent):
    frame = ttk.Frame(parent)

    lbl_msg = ttk.Label(frame, 
                wraplength=550, 
                justify='left', 
                text=txt.END_TIME)
    lbl_msg.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    btn1 = ttk.Button(frame, text=txt.CLOSE, command=quit_app)
    btn1.pack(ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

    WIDGETS[wcn.FRAME_END] = frame
    WIDGETS[wcn.FRE_END_MSG] = lbl_msg
    WIDGETS[wcn.FRE_OK_BUTTON] = btn1

    return frame

def show_frame_end():
    WIDGETS[wcn.FRAME_END].pack(expand=1, fill=tk.BOTH, 
                                ipadx=IPADX, ipady=IPADY, padx=PADX, pady=PADY)

def hide_frame_end():
    WIDGETS[wcn.FRAME_END].pack_forget()

def on_closing():
    clean_vars()
    ROOT_WINDOW.destroy()

def main_window():
    root = tk.Tk()
    root.title(txt.CUVEX)
    global ROOT_WINDOW
    ROOT_WINDOW = root

    window_width = WINDOW_WIDTH
    window_height = WINDOW_HEIGHT

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    center_x = int(screen_width/2 - window_width / 2)
    center_y = int(screen_height/2 - window_height / 2)

    root.geometry('{}x{}+{}+{}'.format(window_width, window_height, center_x, center_y))
    root.configure(bg=wcn.WINDOW_BACKGROUND_COLOR)

    define_styles()
    open_images()
    create_welcome_frame(root)
    create_open_card_frame(root)
    create_card_info_frame(root)
    create_card_content_frame(root)
    create_end_frame(root)

    show_frame_welcome()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main_window()