#!/usr/bin/python

##########################
# cribdrag - An interactive crib dragging tool
# Daniel Crowley
# Copyright (C) 2013 Trustwave Holdings, Inc.
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
##########################
# Changelog
# 2019-07-11 ~ Modified by Jack Gore
##########################

import sys
import re
import argparse

def sxor(ctext, crib):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    results = []
    crib_len = len(crib)
    positions = len(ctext)-crib_len+1

    for i in range(positions):
        single_result = ''
        for a, b in zip(ctext[i:i+crib_len], crib):
            single_result += chr(ord(a) ^ ord(b))
        results.append(single_result)
    return results

def print_linewrapped(text, line_width=40):
    # prints the given text to the screen, wrapping lines to the provided
    # width.
    text_len = len(text)

    for chunk in range(0, text_len, line_width):
        if chunk > text_len-line_width:
            print(str(chunk), "\t", text[chunk:])
        else:
            print(str(chunk), "\t", text[chunk:chunk+line_width])

def generate_matches(results, charset):
    # Generates a list of tuples of the form (bool, int). The boolean indicates
    # if results[int] matches our charset. The result of this function can then
    # be used to display only matched results to the user.
    matches = []

    for i in range(len(results)): 
        if (re.search(charset, results[i])):
            matches.append((True, i, results[i]))
        else:
            matches.append((False, i, results[i]))

    return matches

def print_matches(matches, f=False):
    # prints the given matches to the screen,will filter out those not matching
    # our charset if filter flag (f) is set to true.
    for match in matches:
        if match[0]:
            print('*** ' + str(match[1]) + ': "' + match[2] + '"')
        elif f == False: # only print non-matching results if filter is off.
            print(str(match[1]) + ': "' + match[2] + '"')

def print_display(msg, key):
    # will print prompts and both of the partially decrypted ciphertexts to the
    # screen.
    print("Your message is currently:")
    print_linewrapped(msg)
    print("Your key is currently:")
    print_linewrapped(key)

def build_parser():
    # Will construc a command line parser to use for this application.
    parser = argparse.ArgumentParser(description='cribdrag, the interactive crib dragging script, allows you to interactively decrypt ciphertext using a cryptanalytic technique known as "crib dragging". This technique involves applying a known or guessed part of the plaintext (a "crib") to every possible position of the ciphertext. By analyzing the result of each operation and the likelihood of the result being a successful decryption based on the expected format and language of the plaintext one can recover the plaintext by making educated guesses and adaptive application of the crib dragging technique.')
    parser.add_argument('ciphertext', help='Ciphertext, encoded in an ASCII hex format (ie. ABC would be 414243)')
    parser.add_argument('-c', '--charset', help='A regex-style character set to be used to identify best candidates for successful decryption (ex: for alphanumeric characters and spaces, use "a-zA-Z0-9 ")', default='a-zA-Z0-9.,?! :;\'"')
    parser.add_argument('-f', '--filter', help='A flag to indicate the default state of filterering matches to True', action='store_true')
    return parser

args = build_parser().parse_args()

ctext = bytes.fromhex(args.ciphertext).decode('utf-8')
ctext_len = len(ctext)
display_ctext = "_" * ctext_len
display_key = "_" * ctext_len

charset = '^['+args.charset+']+$'

response = ''

while response != 'end':
    print_display(display_ctext, display_key) 

    crib = input("Please enter your crib: ")
    crib_len = len(crib)

    results = sxor(ctext, crib)
    results_len = len(results)

    matches = generate_matches(results, charset)
    print_matches(matches, args.filter)

    while True: # Repeatedly try to get response in order to replace part of the message or key.
        response = input("Enter the correct position, 'none' for no match, 'filter | f' to toggler filter, or 'end' to quit: ")
        try:
            response = int(response)
            if (response < results_len):
                # Now we need to know if the user wants to replace in the message or in the key.
                message_or_key = ''
                while (message_or_key != 'message' and message_or_key != 'key'):
                    message_or_key = input("Is this crib part of the message or key? Please enter 'message' or 'key': ")
                    if(message_or_key == 'message'):
                        display_ctext = display_ctext[:response] + crib + display_ctext[response+crib_len:]
                        display_key = display_key[:response] + results[response] + display_key[response+crib_len:]
                    elif(message_or_key == 'key'):
                        display_key = display_key[:response] + crib + display_key[response+crib_len:]
                        display_ctext = display_ctext[:response] + results[response] + display_ctext[response+crib_len:]
                    else:
                        print('Invalid response. Try again.')
        except ValueError:
            if response == 'end':
                print("Your message is: " + display_ctext)
                print("Your key is: " + display_key)
                break
            elif response == 'none':
                print("No changes made.")
                break
            elif response == 'filter' or response == 'f':
                print_matches(matches, not args.filter)
            else:
                print("Invalid entry.")

