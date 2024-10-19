# import os
# file = open('tt.bin', "rb")
# buffer = list(file.read())
# print(type(buffer))
# print(buffer)
# file.close()

import os

# from Crypto.Util.Padding import unpad
import multiprocessing as mp
# import pip._vendor.requests
# import json
from Crypto.Cipher import AES


def decryptor(encrypt_file_address, decrypt_file_address, key):
    key = key
    encryptor = AES.new(key, AES.MODE_ECB)
    filename = encrypt_file_address
    chunksize = 16
    newfile = decrypt_file_address
    with open(filename, 'rb') as infile:  # rb means read in binary
        with open(newfile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' '*(16-(len(chunk) % 16))
                outfile.write(encryptor.decrypt(chunk))


def decrypt_files_in_directory(encrypted_file_directory, decrypted_file_directory, key):
    print("converting to decrypt file please wait...")
    for filename in os.listdir(encrypted_file_directory):

        input_file = os.path.join(encrypted_file_directory, filename)
        output_file = os.path.join(decrypted_file_directory, filename)
        decryptor(input_file, output_file, key)


def text_maker(input_bin_address, output_txt_address):
    percent = 0
    percent_help = 0
    filenamebin = input_bin_address
    bin_file = open(filenamebin, 'rb')
    # ---
    filenametxt = output_txt_address
    txt_file = open(filenametxt, 'w')
    # ---
    filesize = os.path.getsize(input_bin_address)
    if filesize > 320:
        info_size = 320
    else:
        info_size = filesize

    bin_file.seek((filesize - info_size))
    ecu_data_buffer_list = list(bin_file.read(info_size))
    bin_file.seek(0)
    # ---
    test_sub_list = list("***#STR:")
    res = []
    add_new = 0
    # a = ord(test_sub_list[0])
    while True:
        try:
            address_help = ecu_data_buffer_list.index(ord("*"), add_new)
            for i in range(len(test_sub_list)):
                if ecu_data_buffer_list[address_help + i] == ord(test_sub_list[i]):
                    notfound = False
                else:
                    add_new = address_help + 1
                    notfound = True
                    break

        except ValueError:
            break

        if notfound == False:
            res.append(address_help)
            add_new = address_help + 8

    # res = [i for i in range(len(ecu_data_buffer))
    #      if ecu_data_buffer.startswith(test_sub, i)]
    for count in range(len(res)):
        str_final = ""
        list_help = 0
        if count == (len(res) - 1):
            # str_help = ecu_data_buffer[(res[count] + 8):]
            list_help = (ecu_data_buffer_list[(res[count] + 8):])
        else:
            # str_help = ecu_data_buffer[(res[count] + 8): (res[count + 1])]
            list_help = (ecu_data_buffer_list[(
                res[count] + 8): (res[count + 1])])

        for i in range(len(list_help)):
            if list_help[i] > 31:
                str_final = str_final + chr(list_help[i])
            else:
                str_final = str_final + " "

        str_final = str_final + "\n"
        try:
            txt_file.write(str_final)
        except:
            txt_file.write(str_final[:16] + "\n")

    txt_file.write("//----------\n")
    # end ecu_info
    total_manitor_size = filesize - info_size + res[0]
    ecu_monitor_buffer_list = list(bin_file.read(total_manitor_size))
    # is can? or kline:
    id_send_can = [0x07, 0xE0, 0x07, 0xE7, 0x07, 0xA5, 0x07, 0x41, 0x07, 0x41, 0x07, 0x50, 0x07, 0x50, 0x07, 0x20, 0x07, 0x20, 0x07, 0x20, 0x07, 0x20, 0x07, 0x23, 0x07, 0x45, 0x07, 0x4C, 0x07, 0x64, 0x07, 0x40, 0x07, 0x40, 0x07,
                   0x4D, 0x07, 0x4D, 0x07, 0x62, 0x07, 0x32, 0x07, 0x00, 0x07, 0x56, 0x07, 0x31, 0x07, 0x60, 0x07, 0x52, 0x07, 0x52, 0x07, 0x01, 0x07, 0x30, 0x07, 0x48, 0x07, 0x61, 0x07, 0x5F, 0x07, 0x42, 0x07, 0x44, 0x07, 0x50, 0x07, 0x64, 0x07, 0x42]
    id_reci_can = [0x07, 0xE8, 0x07, 0xEF, 0x07, 0xAD, 0x06, 0x41, 0x07, 0x61, 0x06, 0x50, 0x07, 0x58, 0x07, 0xA0, 0x07, 0x00, 0x07, 0x40, 0x07, 0x28, 0x07, 0xA3, 0x07, 0x65, 0x07, 0x6C, 0x07, 0x04, 0x07, 0x60, 0x07, 0x50, 0x07,
                   0x6D, 0x07, 0x5D, 0x07, 0x6A, 0x07, 0xB2, 0x07, 0x08, 0x07, 0x5E, 0x07, 0x39, 0x07, 0x70, 0x06, 0x52, 0x07, 0x5A, 0x07, 0x81, 0x07, 0xB0, 0x06, 0x48, 0x07, 0x21, 0x06, 0x5F, 0x06, 0x42, 0x06, 0x44, 0x06, 0x50, 0x07, 0x24, 0x07, 0x02]
    global_can_id = 0
    protocol_is_can = True
    protocol_is_can_help = False
    for i in range(int(len(id_send_can)/2)):
        if ((total_manitor_size > 10) and ecu_monitor_buffer_list[0] == id_send_can[(0 + (2*i))] and ecu_monitor_buffer_list[1] == id_send_can[(1 + (2*i))] and ecu_monitor_buffer_list[10] == id_reci_can[(0 + (2*i))] and ecu_monitor_buffer_list[11] == id_reci_can[(1 + (2*i))]):
            protocol_is_can = True  # is can protocol
            global_can_id = i * 2
            break
        elif (ecu_monitor_buffer_list[0] == id_send_can[(0 + (2*i))] and ecu_monitor_buffer_list[1] == id_send_can[(1 + (2*i))]):
            protocol_is_can_help = True  # is can protocol
            global_can_id_help = i * 2
        else:
            protocol_is_can = False  # is KLINE protocol

    if (protocol_is_can == False and protocol_is_can_help == True):
        global_can_id = global_can_id_help
        protocol_is_can = True

    if protocol_is_can == True:
        global_address = 0
        for x in range(int(total_manitor_size/10)):
            percent = int((x / int(total_manitor_size/10)) * 100)
            if percent_help != percent:
                percent_help = percent
                print(f"{percent} %")

            if (ecu_monitor_buffer_list[global_address] == id_send_can[global_can_id] and ecu_monitor_buffer_list[global_address + 1] == id_send_can[global_can_id + 1]):
                line_string = "Diag: "
            elif (ecu_monitor_buffer_list[global_address] == id_reci_can[global_can_id] and ecu_monitor_buffer_list[global_address + 1] == id_reci_can[global_can_id + 1]):
                line_string = "Node: "
            else:
                break

            line_string = line_string + \
                str(hex(ecu_monitor_buffer_list[global_address]))
            str_help = str(hex(ecu_monitor_buffer_list[global_address + 1]))
            str_help = str_help.upper()
            if (ecu_monitor_buffer_list[global_address + 1] < 10):
                line_string = line_string + "0"

            line_string = line_string + str_help[2:]
            global_address = global_address + 2
            str_help = ""
            for y in range(8):
                if ((ecu_monitor_buffer_list[global_address + y] & 0b11110000) == 0):
                    str_help = "0x0" + \
                        str.upper(
                            hex(ecu_monitor_buffer_list[global_address + y]))[2]
                else:
                    str_help = str.upper(
                        hex(ecu_monitor_buffer_list[global_address + y]))
                    str_help = "0x" + str_help[2:]

                line_string = line_string + ", " + \
                    str_help

            line_string = line_string + "\n\n"
            txt_file.write(line_string)
            global_address = global_address + 8
    else:  # kline
        size_written = 0
        global_address = 0
        diag_address = [0xF1]
        while global_address < (total_manitor_size):
            str_help = ""
            frame_size_help = ecu_monitor_buffer_list[global_address]
            if frame_size_help > 0x80:
                diag_or_node_detection = ecu_monitor_buffer_list[global_address + 2]
                frame_size_help = frame_size_help - 0x80 + 1 + 2 + 1
            elif frame_size_help == 0x80:
                diag_or_node_detection = ecu_monitor_buffer_list[global_address + 2]
                frame_size_help = ecu_monitor_buffer_list[global_address + 3] + 3 + 1 + 1
            elif frame_size_help < 0x80:
                # frame_size_help = frame_size_help + 1 + 1
                # diag_or_node_detection = 0
                line_string = line_string + "can or unknown protocol found! done"
                txt_file.write(line_string)
                break

            for i in range(len(diag_address)):
                if diag_or_node_detection == diag_address[i]:
                    line_string = "Diag: "
                    break
                elif diag_or_node_detection == 0:
                    line_string = "Diag_Or_Node: "
                    break
                else:
                    line_string = "Node: "

            for i in range(frame_size_help):
                if ((ecu_monitor_buffer_list[global_address + i] & 0b11110000) == 0):
                    str_help = "0x0" + \
                        str.upper(
                            hex(ecu_monitor_buffer_list[global_address + i]))[2]
                else:
                    str_help = str.upper(
                        hex(ecu_monitor_buffer_list[global_address + i]))
                    str_help = "0x" + str_help[2:]

                if i == (frame_size_help - 1):
                    line_string = line_string + str_help + "\n\n"
                else:
                    line_string = line_string + str_help + ", "

            size_written = size_written + frame_size_help
            txt_file.write(line_string)
            percent = int((size_written / total_manitor_size) * 100)
            if percent_help != percent:
                percent_help = percent
                print(f"{percent} %")
            global_address = global_address + frame_size_help

    print(f"done making {output_txt_address}")
    txt_file.close()
    bin_file.close()


def make_text_file_from_decrypted_files(decrypted_file_directory, text_file_directory):
    for filename in os.listdir(decrypted_file_directory):
        print(f"converting {filename} to text file please wait...")
        input_file = os.path.join(decrypted_file_directory, filename)
        # ---
        num = filename.find(".bin")
        txt_file_name = filename[0:num] + ".txt"
        output_file = os.path.join(text_file_directory, txt_file_name)
        text_maker(input_file, output_file)


key = bytes.fromhex('34404A643889227367365E3F4F4B4C74')
print(key)
decrypt_files_in_directory('./files/', './decrypted/', key)
# ----------------------------------
make_text_file_from_decrypted_files('./decrypted/', './readable_monitor/')
