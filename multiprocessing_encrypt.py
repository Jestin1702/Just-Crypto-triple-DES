from functools import partial
import DES
import functions
import numpy as np
import bitarray
import time
import multiprocessing
import key_scheduler
import pad
from tkinter import *
from tkinter.ttk import Combobox
from tkinter import filedialog
import hash
import DES_decrypt


obj = functions.Functions()

if __name__ == "__main__":
    win = Tk()
    win.geometry("600x500")

    fun = functions.Functions()

    plaintext = bitarray.bitarray([])
    flag = 0  # flag=0:incomplete parameters, flag=1:Encrypt, flag=2:Decrypt
    no_of_processes = 0
    file_selected = 0
    data_checked = False
    out_dir = ''


    def encrypt_pressed():
        global flag
        flag = 1


    def decrypt_pressed():
        global flag
        flag = 2


    def sel_dir():
        global out_dir
        out_dir = filedialog.askdirectory(parent=win, mode='rb', title='Choose a file')


    def browse():
        global plaintext
        global file_selected
        file = filedialog.askopenfile(parent=win, mode='rb', title='Choose a file')
        in_bytes = np.fromfile(file, dtype="uint8")
        in_bits = np.unpackbits(in_bytes)
        bit_list = in_bits.tolist()
        plaintext = bitarray.bitarray(bit_list)
        file_selected = 1


    l1 = Label(win, text='Just Crypto', font=("Algerian", 30, "bold"),fg="red")
    l2 = Label(win, text='Choose speed',font=15)
    cb = Combobox(win, values=['Slow (Low CPU usage)', 'Medium (default)', 'Fast (High CPU usage)'], state='readonly')
    l3 = Label(win, text='Select the file to encrypt/decrypt',font=15)
    b1 = Button(win, text='Browse', command=browse, bg="orange", fg="red")
    l4 = Label(win, text='Enter the password',font=15)
    t1 = Entry(show='*')
    l5 = Label(win, text='Name of encrypted/decrypted file',font=15)
    t2 = Entry()
    b2 = Button(win, text='Encrypt', command=encrypt_pressed, bg="black", fg="red")
    b3 = Button(win, text='Decrypt', command=decrypt_pressed, bg="black", fg="red")
    l6 = Label(win, text='', font=("Ariel", 9, "bold"))

    l1.place(x=180, y=20)
    l2.place(x=50, y=90)
    cb.place(x=50, y=120)
    l3.place(x=50, y=150)
    b1.place(x=50, y=220)
    b1.configure(borderwidth='1')
    l4.place(x=50, y=190)
    t1.place(x=50, y=250)
    l5.place(x=50, y=290)
    t2.place(x=50, y=320)
    b2.place(x=50, y=385)
    b3.place(x=150, y=385)
    l6.place(x=30, y=405)
    l6.configure(foreground='green')
    l6.config(text='')

    cb.current(1)


    def speed_sel():
        global no_of_processes
        selected = cb.get()
        if selected == 'Slow (Low CPU usage)':
            no_of_processes = 1
        elif selected == 'Medium (default)':
            no_of_processes = 2
        elif selected == 'Fast (High CPU usage)':
            no_of_processes = 3


    win.update()


    def get_data():
        while flag == 0:
            win.update()

        global password, out_name
        speed_sel()
        password = t1.get()
        out_name = t2.get()


    get_data()


    def check_data():
        global flag, data_checked, password, out_name

        while file_selected == 0:
            flag = 0
            l6.config(text='Please select the file')
            win.update()

        if password == '':
            flag = 0
            l6.config(text='Please enter the password')
            get_data()

        if out_name == '':
            flag = 0
            l6.config(text='Please the output file name and Extension')
            get_data()

        if flag != 0:
            data_checked = True


    while not data_checked:
        check_data()


    def demo():
        win.update()

    k = hash.hash_pass(password)  #hash the password using the SHA-256 provided by the hash library to generate a secure 64 bit key

    plaintext = pad.bit_pad(plaintext)  # Pad the plaintext to the nearest byte, ie make the total number of bits, multiple of 8
    plaintext = pad.byte_pad(plaintext)  # Pad the plaintext to make it into 64 bit blocks

    p = []
    for i in range(0, len(plaintext), 64):
        p.append(plaintext[i:i+64])  # Separate the 64 bit blocks

    win.update()

    pool = multiprocessing.Pool(processes=no_of_processes)  #Create a pool object passing the number of processes based on the speed selected by the user

    rkey = key_scheduler.round_key_generator(k)  # Generate the 16 round key and save them here

    start = time.time()  # Time tracking to calculate the speed of encryption/decryption

    if flag == 1:
        abc = partial(DES.des, key=rkey)  # Create a partial
    else:
        abc = partial(DES_decrypt.decrypt_DES, k=rkey)

    ciphertext = pool.map_async(abc, p)  # Start asynchronous multiple processes for encryption/decryption as determined by the partial

    pool.close()  # Close the pool object after all the processes finish

    total_tasks = ciphertext._number_left  # Track the number of tasks left to determine the progress

    '''Progress tracking code'''
    s = '['
    for i in range(50):
        s += ' '  # Create 50 blank blocks for initial process start

    perc_old = 0
    while True:
        if ciphertext.ready():  # if all the processes are complete, stop the tracking
            break

        perc_new = int((total_tasks-ciphertext._number_left) / total_tasks * 100)  # Determine the percentage of the encryption/decryption finished

        if perc_new != perc_old:  # if there is a change in percentage completed
            s = '['
            for i in range(perc_new//2):  # Add the percentage of process complete/2 '|'s (divided by 2 because the maximum number of '|'s that can be added is 50 not 100)
                s += '|'
            for i in range(50-perc_new//2):  # Fill the rest of the blocks with spaces
                s += ' '

        if flag == 1:
            l6.config(text='Encrypting... ' + s + ']' + str(perc_new) + '%')
        else:
            l6.config(text='Decrypting... ' + s + ']' + str(perc_new) + '%')
        win.update()

        perc_old = perc_new

    end = time.time()
    time_taken = end-start

    c = bitarray.bitarray([])

    for i in ciphertext.get():  # Flatten the 2d array that contains 64 bit blocks into a continuous 1d array
        c.extend(i)

    if flag == 2:  # if we did decryption, then remove the paddings
        c = pad.remove_byte_pad(c)
        c = pad.remove_bit_pad(c)

    ciphertext_list = c.tolist()  # convert the bitarray to a python list
    out_bytes = np.packbits(ciphertext_list)
    out_bytes.tofile('Processed files/'+out_name)

    size = len(plaintext)
    speed = (size/time_taken)/1024
    l6.config(text='Process complete!!. Speed: ' + "{:5.2f}".format(speed) + ' kbps')
    # l6.place(x=50, y=375)

    closed = 0

    def close_win():
        global closed
        closed = 1
        win.destroy()

    b4 = Button(win, text='Exit', command=close_win)
    b4.place(x=150, y=750)

    while closed == 0:
        win.update()

