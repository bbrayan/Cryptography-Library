# author Brayan Boukhman
import math
import string
import mod
import matrix
import utilities


# -----------------------------------------------------------
# Parameters:   fileName (string)
# Return:       contents (string)
# Description:  Utility function to read contents of a file
#               Can be used to read plaintext or ciphertext
# -----------------------------------------------------------
def file_to_text(fileName):
    inFile = open(fileName, 'r')
    contents = inFile.read()
    inFile.close()
    return contents

# -----------------------------------------------------------
# Parameters:   text (string)
#               filename (string)
# Return:       none
# Description:  Utility function to write any given text to a file
#               If file already exist, previous content will be over-written
# -----------------------------------------------------------


def text_to_file(text, filename):
    outFile = open(filename, 'w')
    outFile.write(text)
    outFile.close()
    return

# -----------------------------------------------------------
# Parameters:   r: #rows (int)
#               c: #columns (int)
#               pad (str,int,double)
# Return:       empty matrix (2D List)
# Description:  Create an empty matrix of size r x c
#               All elements initialized to pad
#               Default row and column size is 2
# -----------------------------------------------------------


def new_matrix(r, c, pad):
    r = r if r >= 2 else 2
    c = c if c >= 2 else 2
    return [[pad] * c for i in range(r)]

# -----------------------------------------------------------
# Parameters:   marix (2D List)
# Return:       None
# Description:  prints a matrix each row in a separate line
#               Assumes given parameter is a valid matrix
# -----------------------------------------------------------


def print_matrix(matrix):
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            print(matrix[i][j], end='\t')
        print()
    return
# -----------------------------------------------------------
# Parameters:   marix (2D List)
# Return:       text (string)
# Description:  convert a 2D list of characters to a string
#               left to right, then top to bottom
#               Assumes given matrix is a valid 2D character list
# -----------------------------------------------------------


def matrix_to_string(matrix):
    text = ""
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            text += matrix[i][j]
    return text

# --------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (string)
# Return:       ciphertext (string)
# Description:  Encryption using Scytale Cipher
#               Key is the diameter, i.e. # rows
#               Assume infinte length rod (infinte #columns)
# --------------------------------------------------------------


def e_scytale(plaintext, key):
    # By definition, number of rows is key
    r = int(key)
    # number of columns is the length of ciphertext/# rows
    c = int(math.ceil(len(plaintext)/key))
    # create an empty matrix for ciphertext rxc
    cipherMatrix = new_matrix(r, c, "")

    # fill matrix horizontally with characers, pad empty slots with -1
    counter = 0
    for i in range(r):
        for j in range(c):
            cipherMatrix[i][j] = plaintext[counter] if counter < len(
                plaintext) else -1
            counter += 1

    # convert matrix into a string (vertically)
    ciphertext = ""
    for i in range(c):
        for j in range(r):
            if cipherMatrix[j][i] != -1:
                ciphertext += cipherMatrix[j][i]
    return ciphertext


# ---------------------------------
#       Problem 1                #
# ---------------------------------

# ----------------------------------------------------
# Parameters:   ciphertext(string)
#               key (string)
# Return:       plaintext (string)
# Description:  Decryption using Scytale Cipher
#               Assumes key is a valid integer in string format
# ---------------------------------------------------
def d_scytale(ciphertext, key):
    plaintext = ''
    c = int(math.ceil(len(ciphertext) / key))
    plaintext = e_scytale(ciphertext, c)
    return plaintext

# ---------------------------------
#       Problem 2                #
# ---------------------------------

# -----------------------------------------------------------
# Parameters:   dictFile (string): filename
# Return:       list of words (list)
# Description:  Reads a given dictionary file
#               dictionary file is assumed to be formatted: each word in a separate line
#               Returns a list of strings, each pertaining to a dictionary word
# -----------------------------------------------------------


def load_dictionary(dictFile):
    dictList = []
    # your code here
    fv = open(dictFile, "r", encoding="mbcs")
    line = fv.readline()
    while line != "":
        dictList.append(line.strip('\n'))
        line = fv.readline()
    return dictList

# -------------------------------------------------------------------
# Parameters:   text (string)
# Return:       list of words (list)
# Description:  Reads a given text
#               Each word is saved as an element in a list.
#               Returns a list of strings, each pertaining to a word in file
#               Gets rid of all punctuation at the start and at the end
# -------------------------------------------------------------------


def text_to_words(text):
    wordList = []
    # your code here
    no_punc = ''
    punctuations = set(string.punctuation)
    for char in text:
        if char not in punctuations:
            no_punc += char

    wordList = no_punc.split()
    return wordList

# -----------------------------------------------------------
# Parameters:   text (string)
#               dictFile (string): dictionary file
# Return:       (#matches, #mismatches)
# Description:  Reads a given text, checks if each word appears in dictionary
#               Returns a tuple of number of matches and number of mismatches.
#               Words are compared in lowercase.
# -----------------------------------------------------------


def analyze_text(text, dictFile):
    matches = 0
    mismatches = 0
    # your code here
    dictList = load_dictionary(dictFile)
    wordList = text_to_words(text)
    for word in wordList:
        if word.lower() in dictList:
            matches += 1
        else:
            mismatches += 1
    return(matches, mismatches)

# -----------------------------------------------------------
# Parameters:   text (string)
#               dictFile (string): dictionary file
#               threshold (float): number between 0 to 1
# Return:       True/False
# Description:  Check if a given file is a plaintext
#               If #matches/#words >= threshold --> True
#                   otherwise --> False
#               If invalid threshold given, default is 0.9
#               An empty string is assumed to be non-plaintext.
# -----------------------------------------------------------


def is_plaintext(text, dictFile, threshold):
    # your code here
    if text == "":
        return False

    if not (threshold >= 0 and threshold <= 1):
        threshold = 0.9
    (matches, mismatches) = analyze_text(text, dictFile)

    total_words = matches + mismatches
    if (matches / total_words) >= threshold:
        return True
    return False

# ---------------------------------
#       Problem 3                #
# ---------------------------------

# ----------------------------------------------------
# Parameters:   cipherFile (string)
#               dictFile (string)
#               startKey (int)
#               endKey (int)
#               threshold (float)
# Return:       key (string)
# Description:  Apply brute-force to break scytale cipher
#               Valid key range: 2-100 (if invalid --> print error msg and return '')
#               Valid threshold: 0-1 (if invalid --> print error msg and return '')
#               If decryption is successful --> print plaintext and return key
#               If decrytpoin fails: print error msg and return ''
# ---------------------------------------------------


def cryptanalysis_scytale(cipherFile, dictFile, startKey, endKey, threshold):
    # your code here
    if not (startKey >= 2 and endKey <= 100):
        print("Invalid key range. Operation aborted!")
        print("Returned Key = ")
        return

    if not (threshold >= 0 and threshold <= 1):
        print("Invalid threshold value. Operation aborted!")
        print("Returned Key = ")
        return

    for i in range(startKey, endKey):
        plaintext = d_scytale(cipherFile, i)
        if is_plaintext(plaintext, dictFile, threshold):
            print("Key found:", i)
            print(plaintext)
            print("Returned Key", i)
            return i
        else:
            print("key {%d} failed", i)
    return

# ---------------------------------
#       Problem 4                #
# ---------------------------------

# ----------------------------------------------------
# Parameters:   None
# Return:       polybius_square (string)
# Description:  Returns the following polybius square
#               as a sequential string:
#               [1] [2]  [3] [4] [5] [6] [7] [8]
#           [1]      !    "   #   $   %   &   '
#           [2]  (   )    *   +   '   -   .   /
#           [3]  0   1    2   3   4   5   6   7
#           [4]  8   9    :   ;   <   =   >   ?
#           [5]  @   A    B   C   D   E   F   G
#           [6]  H   I    J   K   L   M   N   O
#           [7]  P   Q    R   S   T   U   V   W
#           [8]  X   Y    Z   [   \   ]   ^   _
# ---------------------------------------------------


def get_polybius_square():
    polybius_square = ''
    # your code here
    for i in range(32, 96):
        polybius_square += chr(i)
    return polybius_square

# --------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (none)
# Return:       ciphertext (string)
# Description:  Encryption using Polybius Square
# --------------------------------------------------------------


def e_polybius(plaintext, key):
    ciphertext = ''
    # your code here
    for char in plaintext:
        # finding row of the table
        row = int((ord(char) - ord(' ')) / 8) + 1

        # finding column of the table
        col = ((ord(char) - ord(' ')) % 8) + 1

        ciphertext = ciphertext + str(row) + str(col)
    return ciphertext

# -------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (none)
# Return:       plaintext (string)
# Description:  Decryption using Polybius Square Cipher
#               Detects invalid ciphertext --> print error msg and return ''
#               Case 1: #of chars (other than \n) is not even
#               Case 2: the ciphertext contains non-numerical chars (except \n')
# -------------------------------------------------------


def d_polybius(ciphertext, key):
    plaintext = ''
    square = get_polybius_square()
    i = 0
    if (len(ciphertext) - ciphertext.count('\n')) % 2 != 0:
        print("Invalid ciphertext! Decrypton Failed!")
        return ''

    while i <= len(ciphertext) - 2:
        temp = [ciphertext[i], ciphertext[i + 1]]
        if temp[0] == '\n':
            plaintext += '\n'
            i += 1
        elif temp[0].isdigit() and temp[1].isdigit():
            if int(temp[0]) > 0 and int(temp[1]) > 0:
                index = int((int(temp[0]) - 1) * 8 + int(temp[1])) - 1
                i += 2
                plaintext += square[index]
            else:
                print("Invalid ciphertext! Decrypton Failed!")
                return ''
        else:
            print("Invalid ciphertext! Decrypton Failed!")
            return ''
    if plaintext[-1] != '\n' and ciphertext[-1] == '\n':
        plaintext += '\n'
    return plaintext

# -------------------------------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (str): string of any length
# Return:       ciphertext (string)
# Description:  Genereic Encryption scheme using Vigenere Cipher
#               calls proper function depending on key length
#               if len(key) == 1 --> call e_vigenere1
#               else --> call e_vigenere2
#               If invalid key (not string or empty string or non-alpha string) -->
#                   print error and return '',''
# ---------------------------------------------------------------------------------------


def e_vigenere(plaintext, key):
    if not isinstance(key, str) or key == '' or not key.isalpha():
        print('Error (e_vigenere): invalid key!')
        return ''
    key = key.lower()
    if len(key) == 1:
        return e_vigenere1(plaintext, key)
    else:
        return e_vigenere2(plaintext, key)

# -------------------------------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (str): string of anylength
# Return:       ciphertext (string)
# Description:  Genereic Encryption scheme using Vigenere Cipher
#               calls proper function depending on key length
#               if len(key) == 1 --> call d_vigenere1
#               else --> call d_vigenere2
#               If invalid key (not string or empty string or contains no alpha char) -->
#                   print error and return '',''
# ---------------------------------------------------------------------------------------


def d_vigenere(ciphertext, key):
    if not isinstance(key, str) or key == '' or not key.isalpha():
        print('Error (d_vigenere): invalid key!')
        return ''
    key = key.lower()
    if len(key) == 1:
        return d_vigenere1(ciphertext, key)
    else:
        return d_vigenere2(ciphertext, key)

# -------------------------------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (str): single character
# Return:       ciphertext (string)
# Description:  Encryption using Vigenere Cipher (Polyalphabetic Substitituion)
#               Non alpha characters --> no substitution
#               Algorithm preserves case of the characters
# ---------------------------------------------------------------------------------------


def e_vigenere1(plaintext, key):
    ciphertext = ''
    vigenere_square = utilities.get_vigenereSquare()[ord(key) - ord('a')]

    for c in plaintext:
        if not c.isalpha():
            ciphertext += c
            continue

        if c.lower() != c:
            ciphertext += vigenere_square[ord(c.lower()) - ord('a')].upper()
        else:
            ciphertext += vigenere_square[ord(c.lower()) - ord('a')]

    return ciphertext

# -------------------------------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (str): a phrase
# Return:       ciphertext (string)
# Description:  Encryption using Vigenere Cipher (Polyalphabetic Substitituion)
#               Non alpha characters --> no substitution
#               Algorithm preserves case of the characters
# ---------------------------------------------------------------------------------------


def e_vigenere2(plaintext, key):
    ciphertext = ''
    if len(key) < len(plaintext):
        key = key * int(len(plaintext) / len(key) + 1)

    for i in range(len(plaintext)):
        ciphertext += e_vigenere1(plaintext[i], key[i])

    return ciphertext

# -------------------------------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (str): single character
# Return:       ciphertext (string)
# Description:  Decryption using Vigenere Cipher (Polyalphabetic Substitituion)
#               Non alpha characters --> no substitution
#               Algorithm preserves case of the characters
# ---------------------------------------------------------------------------------------


def d_vigenere1(ciphertext, key):
    plaintext = ''
    reference_square = utilities.get_vigenereSquare()[0]
    vigenere_square = utilities.get_vigenereSquare()[ord(key) - ord('a')]

    for c in ciphertext:
        if not c.isalpha():
            plaintext += c
            continue

        if c.lower() != c:
            plaintext += reference_square[vigenere_square.index(
                c.lower())].upper()
        else:
            plaintext += reference_square[vigenere_square.index(c.lower())]

    return plaintext

# -------------------------------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (str): a phrase
# Return:       ciphertext (string)
# Description:  Decryption using Vigenere Cipher (Polyalphabetic Substitituion)
#               Non alpha characters --> no substitution
#               Algorithm preserves case of the characters
# ---------------------------------------------------------------------------------------


def d_vigenere2(ciphertext, key):
    plaintext = ''
    if len(key) < len(ciphertext):
        key = key * int(len(ciphertext) / len(key) + 1)

    for i in range(len(ciphertext)):
        plaintext += d_vigenere1(ciphertext[i], key[i])

    return plaintext

# -----------------------------------------------------------------------------
# Parameters:   text (string)
#               size (int)
# Return:       list of strings
# Description:  Break a given string into strings of given size
#               Result is provided in a list
# ------------------------------------------------------------------------------


def text_to_blocks(text, size):
    if len(text) % size == 0:
        nBlocks = len(text) // size
    else:
        nBlocks = len(text) // size + 1

    blocks = []

    for i in range(nBlocks):
        start = i * size
        end = start + size
        blocks.append(text[start:end])

    return blocks

# -----------------------------------
# Parameters:   text (string)
# Return:       modifiedText (string)
# Description:  Removes all non-alpha characters from the given string
#               Returns a string of only alpha characters upper case
# -----------------------------------


def remove_nonalpha(text):
    modifiedText = ''

    for c in text:
        if c.isalpha():
            modifiedText += c

    return modifiedText

# -------------------------------------------------------------------------------------
# Parameters:   blocks: list of strings
# Return:       baskets: list of strings
# Description:  Assume all blocks have same size = n (other than last block)
#               Create n baskets
#               In basket[i] put character #i from each block
# ---------------------------------------------------------------------------------------


def blocks_to_baskets(blocks):
    baskets = []

    for i in range(len(blocks[0])):
        basket = ''
        for block in blocks:
            if len(block) > i:
                basket += block[i]
        baskets.append(basket)

    return baskets

# ----------------------------------------------------------------
# Parameters:   ciphertext(string)
# Return:       I (float): Index of Coincidence
# Description:  Computes and returns the index of coincidence
#               for a given text
# ----------------------------------------------------------------


def get_indexOfCoin(ciphertext):
    unique_letters = set(ciphertext.lower())
    numerator = 0

    for letter in unique_letters:
        count = ciphertext.lower().count(letter)
        numerator += count * (count - 1)

    I = numerator / (len(ciphertext) * (len(ciphertext) - 1))

    return I

# ----------------------------------------------------------------
# Parameters:   ciphertext(string)
# Return:       key length (int)
# Description:  Uses Friedman's test to compute key length
#               returns key length rounded to nearest integer
# ---------------------------------------------------------------


def getKeyL_friedman(ciphertext):
    index_of_coincidence = get_indexOfCoin(ciphertext)
    k = round((0.027 * len(ciphertext)) / ((len(ciphertext) - 1) *
                                           index_of_coincidence - 0.038 * len(ciphertext) + 0.065))

    return k

# ----------------------------------------------------------------
# Parameters:   ciphertext(string)
# Return:       key length (int)
# Description:  Uses the Ciphertext Shift method to compute key length
#               Attempts key lengths 1 to 20
# ---------------------------------------------------------------


def getKeyL_shift(ciphertext):
    k = 1
    matches = []

    for i in range(1, 21):
        total_matches = 0
        shift = ''
        shift += ciphertext[i:] + ciphertext[:i]
        for j in range(i, len(ciphertext)):
            if ciphertext[j] == shift[j]:
                total_matches += 1
        matches.append(total_matches)

    k = matches.index(max(matches)) + 1
    return k

# -----------------------------------------------------------
# Parameters:   key (b,r)
# Return:       updatedKey (b,r)
# Description:  Assumes given key is in the format of (b(int),r(int))
#               Updates the key in three scenarios:
#               1- The key is too big (use modulo)
#               2- The key is negative
#               if an invalid key is given print error message and return (0,0)
# -----------------------------------------------------------


def adjustKey_blockRotate(key):
    if not isinstance(key, tuple):
        print("Error (adjustKey_blockRotate): Invalid key", end='')
        return (0, 0)
    b, r = key

    if b < 2:
        print("Error (adjustKey_blockRotate): Invalid key", end='')
        return(0, 0)

    if not isinstance(b, int) or not isinstance(r, int):
        print("Error (adjustKey_blockRotate): Invalid key", end='')
        return(0, 0)
    r %= b
    updatedKey = (b, r)
    return updatedKey

# -----------------------------------
# Parameters:   text (string)
# Return:       nonalphaList (2D List)
# Description:  Analyzes a given string
#               Returns a list of non-alpha characters along with their positions
#               Format: [[char1, pos1],[char2,post2],...]
#               Example: get_nonalpha('I have 3 cents.') -->
#                   [[' ', 1], [' ', 6], ['3', 7], [' ', 8], ['.', 14]]
# -----------------------------------


def get_nonalpha(text):
    nonalphaList = []
    for i in range(len(text)):
        if not text[i].isalpha():
            nonalphaList.append([text[i], i])
    return nonalphaList

# -----------------------------------
# Parameters:   text (str)
#               2D list: [[char1,pos1], [char2,pos2],...]
# Return:       modifiedText (string)
# Description:  inserts a list of nonalpha characters in the positions
# -----------------------------------


def insert_nonalpha(text, nonAlpha):
    modifiedText = text
    for i in range(len(nonAlpha)):
        temp = nonAlpha[i]
        char = temp[0]
        pos = temp[1]
        modifiedText = modifiedText[:pos] + char + modifiedText[pos:]
    return modifiedText

# -----------------------------------------------------------
# Parameters:   plaintext (string)
#               key (b,r): (int,int)
# Return:       ciphertext (string)
# Description:  break plaintext into blocks of size b
#               rotate each block r times to the left
# -----------------------------------------------------------


def e_blockRotate(plaintext, key):
    ciphertext = ''
    nonalpha = get_nonalpha(plaintext)
    plaintext = remove_nonalpha(plaintext)
    b, r = key
    blocks = text_to_blocks(plaintext, b)

    if len(blocks[-1]) < b:
        blocks[-1] = blocks[-1] + 'q' * (b - len(blocks[-1]))
    for i in range(len(blocks)):
        temp = blocks[i]
        temp = temp[r:] + temp[:r]
        blocks[i] = temp
    for i in blocks:
        ciphertext += i

    ciphertext = insert_nonalpha(ciphertext, nonalpha)

    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (string)
#               key (b,r): (int,int)
# Return:       plaintext (string)
# Description:  Decryption using Block Rotate Cipher
# -----------------------------------------------------------


def d_blockRotate(ciphertext, key):
    plaintext = ''
    nonalpha = get_nonalpha(ciphertext)
    ciphertext = remove_nonalpha(ciphertext)
    b, r = key
    blocks = text_to_blocks(ciphertext, b)

    for i in range(len(blocks)):
        temp = blocks[i]
        temp = temp[(b - r):] + temp[:(b - r)]
        blocks[i] = temp
    for i in blocks:
        plaintext += i

    while plaintext[-1] == 'q':
        plaintext = plaintext[:-1]
    plaintext = insert_nonalpha(plaintext, nonalpha)

    return plaintext

# -----------------------------------------------------------
# Parameters:   ciphertext (string)
#               b1 (int): starting block size
#               b2 (int): end block size
# Return:       plaintext,key
# Description:  Cryptanalysis of Block Rotate Cipher
#               Returns plaintext and key (r,b)
#               Attempts block sizes from b1 to b2 (inclusive)
#               Prints number of attempts
# -----------------------------------------------------------


def cryptanalysis_blockRotate(ciphertext, b1, b2):
    plaintext = ''
    key = (0, 0)
    i = 0
    for b in range(b1, b2 + 1):
        for r in range(1, b):
            temp = d_blockRotate(ciphertext, (b, r))
            i += 1
            if utilities.is_plaintext(temp, "engmix.txt", 0.7):
                key = (b, r)
                plaintext = temp
                break
        if plaintext != '':
            break

    if plaintext != '':
        print("Key found after", i, "attempts")
        print("Key =", key)
        print(plaintext)
    else:
        print("Block Rotate Cryptanalysis Failed. No Key was found")
    return plaintext, key


# -----------------------------------------------------------
# Parameters:   ciphertext (string)
# Return:       cipherType (string)
# Description:  Detects the type of a given ciphertext
#               Categories: "Atbash Cipher, Spartan Scytale Cipher,
#                   Polybius Square Cipher, Shfit Cipher, Vigenere Cipher
#                   All other ciphers are classified as Unknown.
#               If the given ciphertext is empty return 'Empty Ciphertext'
# -----------------------------------------------------------
def get_cipherType(ciphertext):
    cipherType = ''
    chi_value_A = 0
    chi_value_B = 0
    chi_value_C = 0

    if ciphertext == '':
        cipherType = 'Empty Ciphertext'
        return cipherType

    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    count = [0] * 26
    frequency_table = utilities.get_freqTable()

    letter_count = 0
    for i in ciphertext:
        if i.isalpha():
            count[alphabet.index(i.lower())] += 1
            letter_count += 1
    if letter_count != 0:
        for i in range(26):
            count[i] /= letter_count

    for i in range(26):
        chi_value_A += ((count[i] - frequency_table[i])
                        ** 2) / frequency_table[i]
        chi_value_B += ((count[i] - frequency_table[25 - i])
                        ** 2) / frequency_table[25 - i]
        chi_value_C += ((count[i] - 0.038) ** 2) / 0.038

    modifiedCiphertext = ciphertext.replace('\n', '')

    if modifiedCiphertext.isdigit():
        cipherType = "Polybius Square Cipher"
    elif chi_value_B < 1:
        cipherType = "Atbash Cipher"
    elif chi_value_A < 2:
        cipherType = "Spartan Scytale Cipher"
    elif 0.1 < chi_value_C < 0.2:
        cipherType = "Vigenere Cipher"
    elif chi_value_A > 2 and 5 > chi_value_C > 0.2:
        cipherType = "Shift Cipher"
    else:
        cipherType = "Unknown"
    return cipherType

# -----------------------------------------------------------
# Parameters:   plaintext (string)
# Return:       modifiedPlain (string)
# Description:  Modify a plaintext through the following criteria
#               1- All non-alpha characters are removed
#               2- Every 'W' is translsated into 'VV' double V
#               3- Convert every double character ## to #X
#               4- if the length of text is odd, add X
#               5- Output is formatted as pairs, separated by space
#                   all upper case
# -----------------------------------------------------------


def formatInput_playfair(plaintext):
    plaintext = plaintext.upper()
    plaintext = remove_nonalpha(plaintext)
    plaintext.replace('W', 'VV')

    for i in range(len(plaintext) - 1):
        if plaintext[i] == plaintext[i + 1]:
            plaintext = plaintext[:i + 1] + 'X' + plaintext[i + 2:]

    if len(plaintext) % 2 != 0:
        plaintext += 'X'

    modifiedPlain = ' '.join(plaintext[i:i + 2]
                             for i in range(0, len(plaintext), 2))

    return modifiedPlain

# -------------------------------------------------------------------------------------
# Parameters:   plaintext(string)
#               key: playfair Square (2D List)
# Return:       ciphertext (string)
# Description:  Encryption using Wheatstone Playfair Cipher
# ---------------------------------------------------------------------------------------


def e_playfair(plaintext, key):
    plaintext = formatInput_playfair(plaintext)
    ciphertext = ''

    for i in range(0, len(plaintext), 3):
        for j in range(len(key)):
            if plaintext[i + 1] in key[j] and plaintext[i] in key[j]:
                x = key[j].index(plaintext[i])
                y = key[j].index(plaintext[i + 1])
                if x == len(key) - 1:
                    ciphertext += key[j][0]
                else:
                    ciphertext += key[j][x + 1]

                if y == len(key) - 1:
                    ciphertext += key[j][0]
                else:
                    ciphertext += key[j][y + 1]
            elif plaintext[i + 1] not in key[j] and plaintext[i] in key[j]:
                x = key[j].index(plaintext[i])
                for z in range(len(key)):
                    if plaintext[i + 1] in key[z]:
                        y = key[z].index(plaintext[i + 1])
                        break

                if x == y:
                    if j == len(key) - 1:
                        ciphertext += key[0][x]
                    else:
                        ciphertext += key[j + 1][x]

                    if z == len(key) - 1:
                        ciphertext += key[0][y]
                    else:
                        ciphertext += key[z + 1][y]
                else:
                    ciphertext += key[j][y]
                    ciphertext += key[z][x]

    ciphertext = " ".join(ciphertext[i:i + 2]
                          for i in range(0, len(ciphertext), 2))
    return ciphertext

# -------------------------------------------------------------------------------------
# Parameters:   plaintext(string)
#               key: playfair Square (2D List)
# Return:       ciphertext (string)
# Description:  Decryption using Wheatstone Playfair Cipher
# -------------------------------------------------------------------------------


def d_playfair(ciphertext, key):
    ciphertext = formatInput_playfair(ciphertext)
    plaintext = ''
    for i in range(0, len(ciphertext), 3):
        for j in range(len(key)):
            if ciphertext[i + 1] in key[j] and ciphertext[i] in key[j]:
                x = key[j].index(ciphertext[i])
                y = key[j].index(ciphertext[i + 1])
                if x == 0:
                    plaintext += key[j][len(key) - 1]
                else:
                    plaintext += key[j][x - 1]

                if y == 0:
                    plaintext += key[j][len(key) - 1]
                else:
                    plaintext += key[j][y - 1]
            elif ciphertext[i + 1] not in key[j] and ciphertext[i] in key[j]:
                x = key[j].index(ciphertext[i])
                for z in range(len(key)):
                    if ciphertext[i + 1] in key[z]:
                        y = key[z].index(ciphertext[i + 1])
                        break

                if x == y:
                    if j == 0:
                        plaintext += key[len(key) - 1][x]
                    else:
                        plaintext += key[j - 1][x]

                    if z == 0:
                        plaintext += key[len(key) - 1][y]
                    else:
                        plaintext += key[z - 1][y]
                else:
                    plaintext += key[j][y]
                    plaintext += key[z][x]

    plaintext = " ".join(plaintext[i:i + 2]
                         for i in range(0, len(plaintext), 2))
    return plaintext

# -----------------------------------------------------------
# Parameters:   key (string)
# Return:       keyOrder (list)
# Description:  checks if given key is a valid columnar transposition key
#               Returns key order, e.g. [face] --> [1,2,3,0]
#               Removes repititions and non-alpha characters from key
#               If empty string or not a string -->
#                   print an error msg and return [0] (which is a)
#               Upper 'A' and lower 'a' are the same order
# -----------------------------------------------------------


def get_keyOrder_columnarTrans(key):
    # your code here
    keyOrder = []
    modifiedText = ''

    if not isinstance(key, str):
        return 'Error: Invalid Columnar Transposition Key [0]'

    # Removing non-alpha
    for c in key:
        if c.isalpha():
            modifiedText += c

    key = modifiedText

    if key == '':
        return 'Error: Invalid Columnar Transposition Key [0]'

    key = key.upper()

    # Removing duplicates
    key_chars = list(key)
    index = 0
    for i in range(0, len(key_chars)):
        for j in range(0, i + 1):
            if (key_chars[i] == key_chars[j]):
                break
        if (j == i):
            key_chars[index] = key_chars[i]
            index += 1
    modifiedText = "".join(key_chars[:index])
    key = modifiedText

    count = 0
    for i in range(0, len(key)):
        count = 0
        for j in range(0, len(key)):
            if key[i] == key[j]:
                j += 1
            elif key[i] > key[j]:
                count += 1
        keyOrder.append(count)
    return keyOrder

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               kye (str)
# Return:       ciphertext (list)
# Description:  Encryption using Columnar Transposition Cipher
# -----------------------------------------------------------


def e_columnarTrans(plaintext, key):
    ciphertext = ''
    keyOrder = get_keyOrder_columnarTrans(key)

    col = len(keyOrder)
    row = int(math.ceil(len(plaintext) / col))

    matrix = [[''] * col for i in range(row)]
    sorted_matrix = [[''] * row for i in range(col)]

    count = 0
    for i in range(0, row):
        for j in range(0, col):
            if count < len(plaintext):
                matrix[i][j] = plaintext[count]
            else:
                matrix[i][j] = 'q'
            count += 1

    for i in range(len(keyOrder)):
        sorted_matrix[keyOrder[i]] = [row[i] for row in matrix]

    for i in range(col):
        for j in range(row):
            ciphertext += sorted_matrix[i][j]
    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               kye (str)
# Return:       plaintext (list)
# Description:  Decryption using Columnar Transposition Cipher
# -----------------------------------------------------------


def d_columnarTrans(ciphertext, key):
    # your code here
    plaintext = ''
    keyOrder = get_keyOrder_columnarTrans(key)

    col = len(keyOrder)
    row = int(math.ceil(len(ciphertext) / col))

    matrix = [[''] * col for i in range(row)]
    sorted_matrix = [[''] * row for i in range(col)]

    count = 0
    for i in range(col):
        for j in range(row):
            if count < len(ciphertext):
                matrix[j][i] = ciphertext[count]
            count += 1

    for i in range(len(keyOrder)):
        sorted_matrix[i] = [row[keyOrder[i]] for row in matrix]

    for i in range(row):
        for j in range(col):
            if sorted_matrix[j][i] != 'q':
                plaintext += sorted_matrix[j][i]
    return plaintext

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key(key,mode)
# Return:       ciphertext (str)
# Description:  Encryption using permutation cipher
#               mode 0: stream cipher --> columnar transposition
#               mode 1: block cipher --> block permutation
#               a padding of 'q' is to be used whenever necessary
# -----------------------------------------------------------


def e_permutation(plaintext, key):
    # your code here
    ciphertext = ''
    key_value = key[0]
    mode_value = key[1]

    if not key_value.isdigit():
        return 'Error (e_permutation): Invalid key'

    if mode_value == 0:
        key_lst = [int(d) for d in key_value]
        col = len(key_lst)
        row = int(math.ceil(len(plaintext) / col))

        matrix = [[''] * col for i in range(row)]
        sorted_matrix = [[''] * row for i in range(col)]

        count = 0
        for i in range(0, row):
            for j in range(0, col):
                if count < len(plaintext):
                    matrix[i][j] = plaintext[count]
                else:
                    matrix[i][j] = 'q'
                count += 1

        for i in range(len(key_lst)):
            sorted_matrix[key_lst[i] - 1] = [row[i] for row in matrix]

        for i in range(col):
            for j in range(row):
                ciphertext += sorted_matrix[i][j]
    elif mode_value == 1:
        key_lst = [int(d) for d in key_value]
        col = len(key_lst)
        row = int(math.ceil(len(plaintext) / col))

        matrix = [[''] * col for i in range(row)]
        sorted_matrix = [[''] * row for i in range(col)]

        count = 0
        for i in range(0, row):
            for j in range(0, col):
                if count < len(plaintext):
                    matrix[i][j] = plaintext[count]
                else:
                    matrix[i][j] = 'q'
                count += 1

        for i in range(len(key_lst)):
            sorted_matrix[i] = [row[key_lst[i] - 1] for row in matrix]

        for i in range(row):
            for j in range(col):
                ciphertext += sorted_matrix[j][i]
    else:
        return 'Error: (e_permutation) invalid mode'
    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key(key,mode)
# Return:       plaintext (str)
# Description:  Decryption using permutation cipher
#               mode 0: stream cipher --> columnar transposition
#               mode 1: block cipher --> block permutation
#               a padding of 'q' is to be removed
# -----------------------------------------------------------


def d_permutation(ciphertext, key):
    # your code here
    plaintext = ''
    key_value = key[0]
    mode_value = key[1]

    if not key_value.isdigit():
        return 'Error (d_permutation): Invalid key'

    if mode_value == 0:
        key_lst = [int(d) for d in key_value]
        col = len(key_lst)
        row = int(math.ceil(len(ciphertext) / col))

        matrix = [[''] * col for i in range(row)]
        sorted_matrix = [[''] * row for i in range(col)]

        count = 0
        for i in range(col):
            for j in range(row):
                if count < len(ciphertext):
                    matrix[j][i] = ciphertext[count]
                count += 1

        for i in range(len(key_lst)):
            sorted_matrix[i] = [row[key_lst[i] - 1] for row in matrix]

        for i in range(row):
            for j in range(col):
                if sorted_matrix[j][i] != 'q':
                    plaintext += sorted_matrix[j][i]
    elif mode_value == 1:
        key_lst = [int(d) for d in key_value]
        col = len(key_lst)
        row = int(math.ceil(len(ciphertext) / col))

        matrix = [[''] * col for i in range(row)]
        sorted_matrix = [[''] * row for i in range(col)]

        count = 0
        for i in range(0, row):
            for j in range(0, col):
                if count < len(ciphertext):
                    matrix[i][j] = ciphertext[count]
                count += 1

        for i in range(len(key_lst)):
            sorted_matrix[key_lst[i] - 1] = [row[i] for row in matrix]

        for i in range(row):
            for j in range(col):
                if sorted_matrix[j][i] != 'q':
                    plaintext += sorted_matrix[j][i]
    else:
        return 'Error: (d_permutation) invalid mode'
    return plaintext

# --------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (string)
# Return:       ciphertext (string)
# Description:  Encryption using ADFGVX cipher
# --------------------------------------------------------------


def e_adfgvx(plaintext, key):
    # your code here
    ciphertext = ''
    polybius = ''
    square = utilities.get_adfgvx_square()
    cipher = ['a', 'd', 'f', 'g', 'v', 'x']
    r = 0
    c = 0
    index = [r, c]

    for c in plaintext:
        if c.isalnum():
            index = utilities.index_matrix(c.upper(), square)
            if c.islower():
                polybius = polybius + cipher[index[0]] + cipher[index[1]]
            elif c.isupper():
                polybius = polybius + \
                    cipher[index[0]].upper() + cipher[index[1]].upper()
        else:
            polybius += c

    ciphertext = e_columnarTrans(polybius, key)
    return ciphertext

# --------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (string)
# Return:       plaintext (string)
# Description:  Decryption using ADFGVX cipher
# --------------------------------------------------------------


def d_adfgvx(ciphertext, key):
    # your code here
    plaintext = ''
    polybius = ''
    decrypted_word = ''

    r = 0
    c = 0
    square = utilities.get_adfgvx_square()
    cipher = ['a', 'd', 'f', 'g', 'v', 'x']

    polybius = d_columnarTrans(ciphertext, key)
    polybius_lst = polybius.split(' ')

    for encrypted_word in polybius_lst:
        decrypted_word = ''
        for (c1, c2) in zip(encrypted_word[0::2], encrypted_word[1::2]):
            r = cipher.index(c1.lower())
            c = cipher.index(c2.lower())
            if c1.islower() and c2.islower():
                decrypted_word += square[r][c].lower()
            else:
                decrypted_word += square[r][c]

        for c in encrypted_word:
            if not c.isalnum():
                decrypted_word += c
        plaintext = plaintext + decrypted_word + ' '

    plaintext = plaintext.strip()
    return plaintext

# --------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (string)
# Return:       ciphertext (string)
# Description:  Encryption using One Time Pad
#               Result is shifted by 32
# --------------------------------------------------------------


def e_otp(plaintext, key):
    # your code here
    ciphertext = ''
    if len(key) != len(plaintext):
        return 'Error: the key and the plaintext must share the same length!'

    for i in range(len(plaintext)):
        ciphertext += chr(ord(xor_otp(plaintext[i], key[i])) + 32)
    return ciphertext

# --------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (string)
# Return:       plaintext (string)
# Description:  Decryption using One Time Pad
#               Input is shifted by 32
# --------------------------------------------------------------


def d_otp(ciphertext, key):
    # your code here
    plaintext = ''
    unshift = ''
    if len(key) != len(ciphertext):
        return 'Error: the key and the ciphertext must share the same length!'

    for i in range(len(ciphertext)):
        unshift += chr(ord(ciphertext[i]) - 32)

    for i in range(len(unshift)):
        plaintext += xor_otp(unshift[i], key[i])
    return plaintext
# --------------------------------------------------------------
# Parameters:   char1 (str)
#               char2 (str)
# Return:       result (str)
# Description:  Takes two characters. Convert their corresponding
#               ASCII value into binary (8-bits), then performs xor
#               operation. The result is treated as an ASCII value
#               which is converted to a character
# --------------------------------------------------------------


def xor_otp(char1, char2):
    # your code here
    ascii_char1 = ord(char1)
    ascii_char2 = ord(char2)

    bin1 = bin(ascii_char1)
    bin2 = bin(ascii_char2)

    xor_result = int(bin1, 2) ^ int(bin2, 2)
    result = chr(xor_result)
    return result

# -----------------------------------------------------------
# Parameters:   key (string)
# Return:       keyOrder (list)
# Description:  checks if given key is a valid Myszkowski key
#               Returns key order, e.g. [meeting] --> [3,0,0,5,2,4,1]
#               The key should have some characters that are repeated
#               and some characters that are non-repeated.
#               if invalid key --> return [1,1,0]
#               Upper and lower case characters are considered of same order
#               non-alpha characters sould be ignored
# -----------------------------------------------------------


def get_keyOrder_myszkowski(key):
    if not isinstance(key, str) or not key:
        print("Error: Invalid Myszkowski Key", end=' ')
        return [1, 1, 0]

    key = utilities.remove_nonalpha(key)
    modified_key = {}

    i = 0
    while i < len(key):
        if key[i].lower() in modified_key:
            modified_key[key[i].lower()] += 1
        else:
            modified_key[key[i].lower()] = 1
        i += 1

    if len(modified_key) == 1:
        return [1, 1, 0]

    duplicate = True

    i = 0
    while i < len(modified_key):
        if modified_key[key[i]] > 1:
            duplicate = False
        i += 1

    if duplicate:
        return [1, 1, 0]

    keyOrder = [0] * len(key)
    temp = [0] * len(key)

    i = 0
    while i < len(key):
        temp[i] = ord(key[i].lower())
        i += 1
    temp.sort()

    i = 0
    while i < len(key):
        temp[i] = chr(temp[i]).lower()
        i += 1

    unique_keys = []

    i = 0
    while i < len(temp):
        if temp[i] not in unique_keys:
            unique_keys.append(temp[i])
        i += 1

    i = 0
    while i < len(key):
        keyOrder[i] = unique_keys.index(key[i].lower())
        i += 1
    return keyOrder

# --------------------------------------------------------------
# Parameters:   plaintext(string)
#               key (string)
# Return:       ciphertext (string)
# Description:  Encryption using Myszkowsi Transposition
# --------------------------------------------------------------


def e_myszkowski(plaintext, key):
    ciphertext = ''
    keyOrder = get_keyOrder_myszkowski(key)
    col = list()

    for i in range(len(keyOrder)):
        col.append(list())

    index = 0
    for letter in plaintext:
        if index >= len(col):
            index = 0

        col[index].append(letter)
        index += 1

    if len(col[-1]) < len(col[0]):
        for i in range(len(col) - 1, 0, -1):
            if len(col[i]) < len(col[0]):
                col[i].append('q')

    maximum = max(keyOrder)
    for i in range(len(set(keyOrder))):
        minimum = min(keyOrder)
        if keyOrder.count(minimum) > 1:
            indices = [i for i, x in enumerate(keyOrder) if x == minimum]
            for i in range(len(col[minimum])):
                for index in indices:
                    ciphertext += col[index][i]
            for index in indices:
                keyOrder[index] = maximum + 1
        else:
            index = keyOrder.index(minimum)
            ciphertext += ''.join(col[index])
            keyOrder[index] = maximum + 1

    return ciphertext

# --------------------------------------------------------------
# Parameters:   ciphertext(string)
#               key (string)
# Return:       plaintext (string)
# Description:  Decryption using Myszkowsi Transposition
# --------------------------------------------------------------


def d_myszkowski(ciphertext, key):
    plaintext = ''
    key_order = get_keyOrder_myszkowski(key)
    col_size = len(ciphertext) // len(key_order)
    col = list()
    for i in range(len(key_order)):
        col.append(list())
    maximum = max(key_order)

    for i in range(len(set(key_order))):
        minimum = min(key_order)
        min_count = key_order.count(minimum)
        if min_count > 1:
            indices = [i for i, x in enumerate(key_order) if x == minimum]
            combined_col = ciphertext[:col_size * min_count]
            ciphertext = ciphertext[col_size * min_count:]

            for i in range(col_size):
                for j in range(len(indices)):
                    col[indices[j]].append(combined_col[i * min_count + j])
            for index in indices:
                key_order[index] = maximum + 1
        else:
            index = key_order.index(minimum)
            column = ciphertext[:col_size]
            ciphertext = ciphertext[col_size:]
            col[index].extend(list(column))
            key_order[index] = maximum + 1
    current_col = -1

    while col[current_col][-1] == 'q':
        col[current_col].pop(-1)
        current_col -= 1
    for i in range(col_size):
        for j in range(len(col)):
            if i < len(col[j]):
                plaintext += col[j][i]
    return plaintext


def cryptanalysis1_myszkowski(ciphertext):
    plaintext = ''
    dictFile = utilities.load_dictionary('engmix.txt')
    keys = [['a', 'b', 'a'], ['b', 'b', 'a'], ['a', 'b', 'b'],
            ['b', 'a', 'b'], ['a', 'a', 'b'], ['b', 'a', 'a']]
    count = 0

    for key in keys:
        count += 1
        result_key = key[0] + key[1] + key[2]
        plaintext = d_myszkowski(ciphertext, result_key)
        if utilities.is_plaintext(plaintext, dictFile, 0.9):
            print("key found after", count, "attempts")
            break

    key = ''.join(key)
    return plaintext, key


def cryptanalysis2_myszkowski(ciphertext, length):
    plaintext = ''
    keys = []
    error_case = [1, 1, 0]
    dictFile = utilities.load_dictionary('engmix.txt')
    fv = open('engmix.txt', 'r', encoding='utf8', errors='ignore')
    line = fv.readline()

    while line != '':
        for word in line.split():
            if len(word) == length and get_keyOrder_myszkowski(word) != error_case:
                keys.append(word)
        line = fv.readline()

    count = 0
    for word in keys:
        count += 1
        plaintext = d_myszkowski(ciphertext, word)
        if utilities.is_plaintext(plaintext, dictFile, 0.9):
            print("key found after", count, "attempts")
            break
    key = word
    fv.close()
    return plaintext, key


def cryptanalysis3_myszkowski(ciphertext):
    plaintext = ''
    keys = []
    error_case = [1, 1, 0]
    dictFile = utilities.load_dictionary('engmix.txt')
    fv = open('engmix.txt', 'r', encoding='utf8', errors='ignore')
    line = fv.readline()

    while line != '':
        for word in line.split():
            unique_chars = set(word)
            if len(word) == 5 and len(unique_chars) == 3:
                for char in unique_chars:
                    if word.count(char) == 3 and get_keyOrder_myszkowski(word) != error_case:
                        keys.append(word)
        line = fv.readline()

    count = 0
    for word in keys:
        count += 1
        plaintext = d_myszkowski(ciphertext, word)
        if utilities.is_plaintext(plaintext, dictFile, 0.9):
            print("key found after", count, "attempts")
            break
    key = word
    fv.close()
    return plaintext, key

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str,int)
# Return:       ciphertext (str)
# Description:  Encryption using Decimation Cipher
#               key is tuple (baseString,k)
#               Does not encrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key has no multiplicative inverse -->
#                   print error msg and return empty string
# -----------------------------------------------------------


def e_decimation(plaintext, key):
    # your code here
    ciphertext = ''
    baseString = key[0]
    encrypt_value = key[1]

    if not mod.has_mul_inv(encrypt_value, len(baseString)):
        print('Error (e_decimation): Invalid key')
        return ''

    for char in plaintext:
        if char.lower() in baseString:
            if char.isupper():
                alphaPos = baseString.index(char.lower())
                result = alphaPos * encrypt_value
                if result > len(baseString):
                    new_result = result % len(baseString)
                    ciphertext += baseString[new_result].upper()
                else:
                    ciphertext += baseString[result].upper()
            else:
                alphaPos = baseString.index(char)
                result = alphaPos * encrypt_value
                if result > len(baseString):
                    new_result = result % len(baseString)
                    ciphertext += baseString[new_result]
                else:
                    ciphertext += baseString[result]
        else:
            ciphertext += char
    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str,int)
# Return:       plaintext (str)
# Description:  Decryption using Decimation Cipher
#               key is tuple (baseString,k)
#               Does not decrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key has no multiplicative inverse -->
#                   print error msg and return empty string
# -----------------------------------------------------------


def d_decimation(ciphertext, key):
    # your code here
    plaintext = ''
    baseString = key[0]
    decrypt_value = mod.mul_inv(key[1], len(baseString))

    if not mod.has_mul_inv(key[1], len(baseString)):
        print('Error (d_decimation): Invalid key')
        return ''

    for char in ciphertext:
        if char.lower() in baseString:
            if char.isupper():
                alphaPos = baseString.index(char.lower())
                result = alphaPos * decrypt_value
                if result > len(baseString):
                    new_result = result % len(baseString)
                    plaintext += baseString[new_result].upper()
                else:
                    plaintext += baseString[result].upper()
            else:
                alphaPos = baseString.index(char)
                result = alphaPos * decrypt_value
                if result > len(baseString):
                    new_result = result % len(baseString)
                    plaintext += baseString[new_result]
                else:
                    plaintext += baseString[result]
        else:
            plaintext += char

    return plaintext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext,key
# Description:  Cryptanalysis of Decimation Cipher
# -----------------------------------------------------------


def cryptanalysis_decimation(ciphertext):
    # your code here
    baseString = utilities.get_baseString()
    dictList = utilities.load_dictionary('engmix.txt')

    tries = 0
    x = 26
    while x < len(baseString):
        subString = baseString[:x]
        for i in range(len(subString)):
            if mod.is_relatively_prime(i, len(subString)):
                plaintext = d_decimation(ciphertext, (subString, i))
                if plaintext is None:
                    continue
                tries += 1
                if utilities.is_plaintext(plaintext.lower(), dictList, 0.95):
                    print('Key found after {} attempts'.format(tries))
                    return plaintext, (subString, i)
        x += 1
    return '', ''

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str,[int,int])
# Return:       ciphertext (str)
# Description:  Encryption using Affine Cipher
#               key is tuple (baseString,[alpha,beta])
#               Does not encrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key can not be used for decryption
#                   print error msg and return empty string
# -----------------------------------------------------------


def e_affine(plaintext, key):
    # your code here
    baseString = key[0]
    key_values = key[1]
    alpha = key_values[0]
    beta = key_values[1]
    ciphertext = ''

    if not mod.is_relatively_prime(alpha, len(baseString)):
        print("Error (e_affine): Invalid key")
        return ''

    for char in plaintext:
        if char.lower() in baseString:
            if char.isupper():
                alphaPos = baseString.index(char.lower())
                encrypt_value = (alphaPos * alpha + beta) % len(baseString)
                ciphertext += baseString[encrypt_value].upper()
            else:
                alphaPos = baseString.index(char)
                encrypt_value = (alphaPos * alpha + beta) % len(baseString)
                ciphertext += baseString[encrypt_value]
        else:
            ciphertext += char
    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str,[int,int])
# Return:       plaintext (str)
# Description:  Decryption using Affine Cipher
#               key is tuple (baseString,[alpha,beta])
#               Does not decrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key can not be used for decryption
#                   print error msg and return empty string
# -----------------------------------------------------------


def d_affine(ciphertext, key):
    # your code here
    baseString = key[0]
    key_values = key[1]
    alpha = key_values[0]
    beta = key_values[1]
    plaintext = ''

    if not mod.is_relatively_prime(alpha, len(baseString)):
        print("Error (d_affine): Invalid key")
        return ''

    alpha_inv = mod.mul_inv(alpha, len(baseString))

    for char in ciphertext:
        if char.lower() in baseString:
            if char.isupper():
                alphaPos = baseString.index(char.lower())
                decrypt_value = alpha_inv * (alphaPos - beta) % len(baseString)
                plaintext += baseString[decrypt_value].upper()
            else:
                alphaPos = baseString.index(char)
                decrypt_value = alpha_inv * (alphaPos - beta) % len(baseString)
                plaintext += baseString[decrypt_value]
        else:
            plaintext += char
    return plaintext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext,key
# Description:  Cryptanalysis of Affine Cipher
# -----------------------------------------------------------


def cryptanalysis_affine(ciphertext):
    # your code here
    plaintext = ''
    baseString = utilities.get_baseString()
    dictList = utilities.load_dictionary('engmix.txt')
    tries = 0
    x = 26

    while x < len(baseString):
        subString = baseString[:x]
        for i in range(len(subString)):
            for j in range(len(subString)):
                key = (subString, [i, j])
                if mod.is_relatively_prime(i, len(subString)):
                    plaintext = d_affine(ciphertext, key)
                    if plaintext is None:
                        continue
                    tries += 1
                    if utilities.is_plaintext(plaintext.lower(), dictList, 0.9):
                        print('key found after {} attempts'.format(tries))
                        return plaintext, key
        x += 1
    return '', ''

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str)
# Return:       ciphertext (str)
# Description:  Encryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Encrypts only alphabet
#               Case of characters can be ignored --> cipher is upper case
#               If necessary pad with 'Q'
# Errors:       if key is not inveritble or if plaintext is empty
#                   print error msg and return empty string
# -----------------------------------------------------------


def e_hill(plaintext, key):
    if plaintext == '':
        print('Error (e_hill): Invalid plaintext')
        return ''

    if len(key) == 1:
        key = key * 4
    elif len(key) == 2:
        key = key * 2
    elif len(key) == 3:
        key = key + key[0]
    elif len(key) > 4:
        key = key[:4]

    key = key.upper()
    alphabet = utilities.get_lower().upper()

    pos_1 = alphabet.index(key[0])
    pos_2 = alphabet.index(key[1])
    pos_3 = alphabet.index(key[2])
    pos_4 = alphabet.index(key[3])

    key_matrix = [[pos_1, pos_2], [pos_3, pos_4]]
    key_inv = matrix.inverse(key_matrix, len(alphabet))

    if isinstance(key_inv, str):
        print('Error (e_hill): key is not invertible')
        return ''

    plaintext = plaintext.upper()
    ciphertext = ''

    i = 0

    while i < len(plaintext):
        if i + 1 == len(plaintext):
            plaintext += 'Q'

        if plaintext[i].isalpha() and plaintext[i + 1].isalpha():
            first_char_pos = alphabet.index(plaintext[i])
            second_char_pos = alphabet.index(plaintext[i + 1])
            matrix_multiplied = matrix.mul(
                key_matrix, [[first_char_pos], [second_char_pos]])
            matrix_mod = matrix.matrix_mod(matrix_multiplied, len(alphabet))
            ciphertext += alphabet[matrix_mod[0][0]] + \
                alphabet[matrix_mod[1][0]]
            i += 2
        else:
            ciphertext += plaintext[i]
            i += 1

    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str)
# Return:       plaintext (str)
# Description:  Decryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Decrypts only alphabet
#               Case of characters can be ignored --> plain is lower case
#               Remove padding of q's
# Errors:       if key is not inveritble or if ciphertext is empty
#                   print error msg and return empty string
# -----------------------------------------------------------


def d_hill(ciphertext, key):
    plaintext = ''
    alphabet = utilities.get_lower().upper()
    key = key.upper()

    if len(ciphertext) == 0:
        print('Error(d_hill): invalid ciphertext')
        return ''

    if len(key) == 1:
        key = key * 4
    elif len(key) == 2:
        key = key * 2
    elif len(key) == 3:
        key = key + key[0]
    elif len(key) > 4:
        key = key[:4]

    nonalpha = utilities.get_nonalpha(ciphertext)
    modified_ciphertext = utilities.remove_nonalpha(ciphertext)
    modified_ciphertext = modified_ciphertext.upper()

    if len(modified_ciphertext) % 2 != 0:
        modified_ciphertext += 'Q'

    count_1, count_2 = 0, 0
    text_matrix = matrix.new_matrix(2, int(len(modified_ciphertext) / 2), 0)
    for i in range(len(modified_ciphertext)):
        if i % 2 == 0:
            text_matrix[0][count_1] = alphabet.find(modified_ciphertext[i])
            count_1 += 1
        else:
            text_matrix[1][count_2] = alphabet.find(modified_ciphertext[i])
            count_2 += 1

    alphabet_key = 'ABCDE'
    pos_1 = alphabet_key.index(key[0])
    pos_2 = alphabet_key.index(key[1])
    pos_3 = alphabet_key.index(key[2])
    pos_4 = alphabet_key.index(key[3])

    key_matrix = [[pos_1, pos_2], [pos_3, pos_4]]
    key_inv = matrix.inverse(key_matrix, len(alphabet))

    for i in range(int(len(modified_ciphertext) / 2)):
        a = text_matrix[0][i] * key_inv[0][0] + \
            text_matrix[1][i] * key_inv[0][1]
        b = text_matrix[0][i] * key_inv[1][0] + \
            text_matrix[1][i] * key_inv[1][1]
        plaintext += alphabet[a % len(alphabet)]
        plaintext += alphabet[b % len(alphabet)]

    plaintext = utilities.insert_nonalpha(plaintext, nonalpha)
    plaintext = plaintext.lower()

    plaintext = plaintext.strip('q')
    return plaintext


configFile = 'SDES_config.txt'
sbox1File = 'sbox1.txt'
sbox2File = 'sbox2.txt'
primeFile = 'primes.txt'

# -----------------------------------------------------------
# Parameters:   c (str): a character
#               codeType (str)
# Return:       b (str): corresponding binary number
# Description:  Generic function for encoding
#               Current implementation supports only ASCII and B6 encoding
# Error:        If c is not a single character:
#                   print('Error(encode): invalid input'), return ''
#               If unsupported encoding type:
#                   print('Error(encode): Unsupported Coding Type'), return ''
# -----------------------------------------------------------


def encode(c, codeType):
    # your coce here
    b = ''
    if not isinstance(c, str):
        print('Error(encode): invalid input')
        return ''

    if len(c) != 1:
        print('Error(encode): invalid input')
        return ''

    if codeType != 'ASCII' and codeType != 'B6':
        print('Error(encode): Unsupported Coding Type')
        return ''

    if codeType == 'ASCII':
        ascii_value = ord(c)
        b = utilities.dec_to_bin(ascii_value, 8)
    else:
        b = encode_B6(c)
    return b

# -----------------------------------------------------------
# Parameters:   b (str): a binary number
#               codeType (str)
# Return:       c (str): corresponding character
# Description:  Generic function for decoding
#               Current implementation supports only ASCII and B6 encoding
# Error:        If c is not a binary number:
#                   print('Error(decode): invalid input',end =''), return ''
#               If unsupported encoding type:
#                   print('Error(decode): Unsupported Coding Type',end =''), return ''
# -----------------------------------------------------------


def decode(b, codeType):
    # your code here
    c = ''

    if not utilities.is_binary(b):
        print('Error(decode): invalid input', end='')
        return ''

    if codeType != 'ASCII' and codeType != 'B6':
        print('Error(decode): Unsupported Coding Type')
        return ''

    if codeType == 'ASCII':
        decimal = int(b, 2)
        c = chr(decimal)
    else:
        c = decode_B6(b)
    return c

# -----------------------------------------------------------
# Parameters:   c (str): a character
# Return:       b (str): 6-digit binary code
# Description:  Encodes any given symbol in the B6 Encoding scheme
#               If given symbol is one of the 64 symbols, the function returns
#               the binary representation, which is the equivalent binary number
#               of the decimal value representing the position of the symbol in the B6Code
#               If the given symbol is not part of the B6Code --> return empty string (no error msg)
# Error:        If given input is not a single character -->
#                   print('Error(encode_B6): invalid input',end =''), return ''
# -----------------------------------------------------------


def encode_B6(c):
    # your code here
    b = ''
    b6Code = utilities.get_B6Code()

    if c not in b6Code:
        return ''

    if not isinstance(c, str):
        print('Error(encode_B6): invalid input', end='')
        return ''

    if len(c) != 1:
        print('Error(encode_B6): invalid input', end='')
        return ''

    index = b6Code.index(c)
    b = utilities.dec_to_bin(index, 8)[2:]
    return b

# -----------------------------------------------------------
# Parameters:   b (str): binary number
# Return:       c (str): a character
# Description:  Decodes any given binary code in the B6 Coding scheme
#               Converts the binary number into integer, then get the
#               B6 code at that position
# Error:        If given input is not a valid 6-bit binary number -->
#                   print('Error(decode_B6): invalid input',end =''), return ''
# -----------------------------------------------------------


def decode_B6(b):
    # your code here
    c = ''
    b6Code = utilities.get_B6Code()

    if not utilities.is_binary(b):
        print('Error(decode_B6): invalid input', end='')
        return ''

    if len(b) != 6:
        print('Error(decode_B6): invalid input', end='')
        return ''

    dec_value = int(b, 2)
    c = b6Code[dec_value]
    return c

# -----------------------------------------------------------
# Parameters:   None
# Return:       paramList (list)
# Description:  Returns a list of parameter names which are used in
#               Configuration of SDES
# Error:        None
# -----------------------------------------------------------


def get_SDES_parameters():
    return ['encoding_type', 'block_size', 'key_size', 'rounds', 'p', 'q']

# -----------------------------------------------------------
# Parameters:   None
# Return:       configList (2D List)
# Description:  Returns the current configuraiton of SDES
#               configuration list is formatted as the following:
#               [[parameter1,value],[parameter2,value2],...]
#               The configurations are read from the configuration file
#               If configuration file is empty --> return []
# Error:        None
# -----------------------------------------------------------


def get_SDES_config():
    # your code here
    configList = []
    fv = open(configFile, 'r')

    line = fv.readline()
    if line == '':
        return []

    while line != '':
        configTokens = line.split(':')
        parameter = configTokens[0]
        value = configTokens[1].strip()
        config = []
        config.append(parameter)
        config.append(value)
        configList.append(config)
        line = fv.readline()

    fv.close()
    return configList

# -----------------------------------------------------------
# Parameters:   parameter (str)
# Return:       value (str)
# Description:  Returns the value of the parameter based on the current
# Error:        If the parameter is undefined in get_SDES_parameters() -->
#                   print('Error(get_SDES_value): invalid parameter',end =''), return ''
# -----------------------------------------------------------


def get_SDES_value(parameter):
    # your code here
    value = ''
    parameters = get_SDES_parameters()
    if parameter not in parameters:
        print('Error(get_SDES_value): invalid parameter', end='')
        return ''

    configList = get_SDES_config()
    for config in configList:
        if config[0] == parameter:
            value = config[1]
            break
    return value

# -----------------------------------------------------------
# Parameters:   parameter (str)
#               value (str)
# Return:       True/False
# Description:  Sets an SDES parameter to the given value and stores
#               the output in the configuration file
#               if the configuration file contains previous value for the parameter
#               the function overrides it with the new value
#               otherwise, the new value is appended to the configuration file
#               Function returns True if set value is successful and False otherwise
# Error:        If the parameter is undefined in get_SDES_parameters() -->
#                   print('Error(cofig_SDES): invalid parameter',end =''), return False
#               If given value is not a string or is an empty string:
#                   print('Error(config_SDES): invalid value',end =''), return 'False
# -----------------------------------------------------------


def config_SDES(parameter, value):
    # your code here
    parameters = get_SDES_parameters()
    if parameter not in parameters:
        print('Error(cofig_SDES): invalid parameter', end='')
        return False

    if not isinstance(value, str):
        print('Error(config_SDES): invalid value', end='')
        return False

    if len(value) == 0:
        print('Error(config_SDES): invalid value', end='')
        return False

    config = parameter + ':' + value + '\n'
    fv_a = open(configFile, 'a')
    fv_r = open(configFile, 'r')

    if parameter in fv_r.read():
        configList = get_SDES_config()
        for element in configList:
            if element[0] == parameter:
                element[1] = value
                break
        open(configFile, 'w').close()
        for element in configList:
            fv_a.write(element[0] + ':' + element[1] + '\n')
        fv_a.close()
        fv_r.close()
        return True
    else:
        fv_a.write(config)
        fv_a.close()
        fv_r.close()
        return True
    return False

# -----------------------------------------------------------
# Parameters:   p (int)
#               q (int)
#               m (int): number of bits
# Return:       bitStream (str)
# Description:  Uses Blum Blum Shub Random Generation Algorithm to generates
#               a random stream of bits of size m
#               The seed is the nth prime number, where n = p*q
#               If the nth prime number is not relatively prime with n,
#               the next prime number is selected until a valid one is found
#               The prime numbers are read from the file primeFile (starting n=1)
# Error:        If number of bits is not a positive integer -->
#                   print('Error(blum): Invalid value of m',end =''), return ''
#               If p or q is not an integer that is congruent to 3 mod 4:
#                   print('Error(blum): Invalid values of p,q',end =''), return ''
# -----------------------------------------------------------


def blum(p, q, m):
    # your code here
    bitStream = ''
    if m <= 0:
        print('Error(blum): Invalid value of m', end='')
        return ''
    if not isinstance(p, int) or not isinstance(q, int):
        print('Error(blum): Invalid values of p,q', end='')
        return ''
    if p % 4 != 3 or q % 4 != 3:
        print('Error(blum): Invalid values of p,q', end='')
        return ''

    n = p * q
    seed = 0
    fv = open(primeFile, 'r')
    strings = fv.read()
    primes = strings.split('\n')

    if not mod.is_relatively_prime(int(primes[n - 1]), n):
        for i in range(n, len(primes)):
            if mod.is_relatively_prime(int(primes[i - 1]), n):
                seed = int(primes[i - 1])
                break

    elif mod.is_relatively_prime(int(primes[n - 1]), n):
        seed = int(primes[n - 1])

    for i in range(m):
        seed = (seed * seed) % n
        temp = mod.residue(seed ** 2, n)
        bitStream += '0' if temp % 2 == 0 else '1'
    return bitStream

# ----------------------------------------------S-------------
# Parameters:   None
# Return:       key (str)
# Description:  Generates an SDES key based on preconfigured values
#               The key size is fetched from the SDES configuration
#               If no key size is available, an error message is printed
#               Also, the values of p and q are fetched as per SDES configuration
#               If no values are found, the default values p = 383 and q = 503 are used
#               These values should be updated in the configuration file
#               The function calls the blum function to generate the key
# Error:        if key size is not defined -->
#                           print('Error(generate_key_SDES):Unknown Key Size',end=''), return ''
# -----------------------------------------------------------


def generate_key_SDES():
    # your code here
    configList = get_SDES_config()
    p = -1
    q = -1
    m = -1

    for config in configList:
        if config[0] == 'p':
            p = int(config[1])
        if config[0] == 'q':
            q = int(config[1])
        if config[0] == 'key_size':
            m = int(config[1])

    if p == -1:
        p = 383

    if q == -1:
        q = 503

    if m == -1:
        print('Error(generate_key_SDES):Unknown Key Size', end='')
        return ''

    key = blum(p, q, m)
    return key

# -----------------------------------------------------------
# Parameters:   key (str)
#               i (int)
# Return:       key (str)
# Description:  Generates a subkey for the ith round in SDES
#               The sub-key is one character shorter than original key size
#               Sub-key is generated by circular shift of key with value 1,
#               where i=1 means no shift
#               The least significant bit is dropped after the shift
# Errors:       if key is not a valid binary number or its length does not match key_size: -->
#                   print('Error(get_subKey): Invalid key',end='')
#               if i is not a positive integer:
#                   print('Error(get_subKey): invalid i',end=''), return ''
# -----------------------------------------------------------


def get_subKey(key, i):
    # your code here
    m = -1
    subKey = ''
    configList = get_SDES_config()
    for config in configList:
        if config[0] == 'key_size':
            m = int(config[1])

    if i <= 0:
        print('Error(get_subKey): Invalid i', end='')
        return ''

    if not utilities.is_binary(key):
        print('Error(get_subKey): Invalid key', end='')
        return ''

    subKey = utilities.shift_string(key, i - 1, 'l')[:-1]
    return subKey

# -----------------------------------------------------------
# Parameters:   R (str): binary number of size (block_size/2)
# Return:       output (str): expanded binary
# Description:  Expand the input binary number by adding two digits
#               The input binary number should be an even number >= 6
#               Expansion works as the following:
#               If the index of the two middle elements is i and i+1
#               From indices 0 up to i-1: same order
#               middle becomes: R(i+1)R(i)R(i+1)R(i)
#               From incides R(i+2) to the end: same order
# Error:        if R not a valid binary number or if it has an odd length
#               or is of length smaller than 6
#                   print('Error(expand): invalid input',end=''), return ''
# -----------------------------------------------------------


def expand(R):
    # your code here
    if not utilities.is_binary(R) or len(R) % 2 != 0 or len(R) < 6:
        print('Error(expand): invalid input', end='')
        return ''

    mid_1 = R[len(R) // 2 - 1]
    mid_2 = R[len(R) // 2]

    output = R[:len(R) // 2 - 1] + mid_2 + mid_1 + \
        mid_2 + mid_1 + R[len(R) // 2 + 1:]
    return output

# -----------------------------------------------------------
# Parameters:   R (str): binary number of size (block_size//4)
# Return:       output (str): binary number
# Description:  Validates that R is of size block_size//4 + 1
#               Retrieves relevant structure of sbox1 from sbox1File
#               Most significant bit of R is row number, other bits are column number
# Error:        if undefined block_size:
#                   print('Error(sbox1): undefined block size',end=''), return ''
#               if invalid R:
#                   print('Error(sbox1): invalid input',end=''),return ''
#               if no sbox1 structure exist:
#                   print('Error(sbox1): undefined sbox1',end=''),return ''
# -----------------------------------------------------------


def sbox1(R):
    # your code here
    configList = get_SDES_config()
    block_size = -1
    output = ''

    for element in configList:
        if element[0] == 'block_size':
            block_size = int(element[1])
            break
    if block_size == -1:
        print('Error(sbox1): undefined block size', end='')
        return ''

    block_size = block_size // 4
    if not utilities.is_binary(R) or len(R) != block_size + 1:
        print('Error(sbox1): invalid input', end='')
        return ''

    fv = open(sbox1File, 'r')
    line = fv.readline()
    count = 1
    index = 0

    if line == '':
        print('Error(sbox1): undefined sbox1', end='')
        return ''

    while line != '':
        if count == block_size:
            sBox1Row = line.split(':')
            sBox1List = sBox1Row[1].split(',')
            index = int(R, 2)
            output = sBox1List[index]
        count += 1
        line = fv.readline()

    output = output.strip()
    return output

# -----------------------------------------------------------
# Parameters:   R (str): binary number of size (block_size//4)
# Return:       output (str): binary
# Description:  Validates that R is of size block_size//4 + 1
#               Retrieves relevant structure of sbox2 from sbox2File
#               Most significant bit of R is row number, other bits are column number
# Error:        if undefined block_size:
#                   print('Error(sbox2): undefined block size',end=''), return ''
#               if invalid R:
#                   print('Error(sbox2): invalid input',end=''),return ''
#               if no sbox1 structure exist:
#                   print('Error(sbox2): undefined sbox1',end=''),return ''
# -----------------------------------------------------------


def sbox2(R):
    # your code here
    configList = get_SDES_config()
    block_size = -1
    output = ''

    for element in configList:
        if element[0] == 'block_size':
            block_size = int(element[1])
            break
    if block_size == -1:
        print('Error(sbox2): undefined block size', end='')
        return ''

    block_size = block_size // 4
    if not utilities.is_binary(R) or len(R) != block_size + 1:
        print('Error(sbox2): invalid input', end='')
        return ''

    fv = open(sbox2File, 'r')
    line = fv.readline()
    count = 1
    index = 0

    if line == '':
        print('Error(sbox2): undefined sbox2', end='')
        return ''

    while line != '':
        if count == block_size:
            sBox2Row = line.split(':')
            sBox2List = sBox2Row[1].split(',')
            index = int(R, 2)
            output = sBox2List[index]
        count += 1
        line = fv.readline()

    output = output.strip()
    return output

# -----------------------------------------------------------
# Parameters:   Ri (str): block of binary numbers
#               ki (str): binary number representing subkey
# Return:       Ri2 (str): block of binary numbers
# Description:  Performs the following five tasks:
#               1- Pass the Ri block to the expander function
#               2- Xor the output of [1] with ki
#               3- Divide the output of [2] into two equal sub-blocks
#               4- Pass the most significant bits of [3] to Sbox1
#                  and least significant bits to sbox2
#               5- Conactenate the output of [4] as [sbox1][sbox2]
# Error:        if ki is an invalid binary number:
#                   print('Error(F): invalid key',end=''), return ''
#               if invalid Ri:
#                   print('Error(F): invalid input',end=''),return ''
# -----------------------------------------------------------


def F(Ri, ki):
    # your code here
    Ri2 = ''
    if not utilities.is_binary(ki) or len(ki) % 2 != 0:
        print('Error(F): invalid key', end='')
        return ''

    if not utilities.is_binary(Ri) or len(Ri) % 2 != 0:
        print('Error(F): invalid input', end='')
        return ''

    expanded_Ri = expand(Ri)
    xor_result = utilities.xor(expanded_Ri, ki)
    sub_block1 = xor_result[:len(xor_result) // 2]
    sub_block2 = xor_result[len(xor_result) // 2:]

    sBox1Result = sbox1(sub_block1)
    sBox2Result = sbox2(sub_block2)

    Ri2 = sBox1Result + sBox2Result
    return Ri2

# -----------------------------------------------------------
# Parameters:   bi (str): block of binary numbers
#               ki (str): binary number representing subkey
# Return:       bi2 (str): block of binary numbers
# Description:  Applies Fiestel Cipher on a block of binary numbers
#               L(current) = R(previous)
#               R(current) = L(previous)xor F(R(previous), subkey)
# Error:        if ki is an invalid binary number or of invalid size
#                   print('Error(feistel): Invalid key',end=''), return ''
#               if invalid Ri:
#                   print('Error(feistel): Invalid block',end=''),return ''
# -----------------------------------------------------------


def feistel(bi, ki):
    if not isinstance(bi, str):
        print('Error(feistel): Invalid block', end='')
        return ''

    if not utilities.is_binary(bi):
        print('Error(feistel): Invalid block', end='')
        return ''

    block_size = int(get_SDES_value('block_size'))
    if len(bi) != block_size:
        print('Error(feistel): Invalid block', end='')
        return ''

    if not isinstance(ki, str) or len(ki) != len(bi) // 2 + 2:
        print('Error(feistel): Invalid key', end='')
        return ''

    if not utilities.is_binary(ki):
        print('Error(feistel): Invalid key', end='')
        return ''

    prev_left = bi[:len(bi) // 2]
    prev_right = bi[len(bi) // 2:]

    temp = prev_right
    prev_right = utilities.xor(prev_left, F(prev_right, ki))
    prev_left = temp

    bi2 = prev_left + prev_right
    return bi2

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str)
# Return:       ciphertext (str)
# Description:  Encryption using Simple DES
# -----------------------------------------------------------


def e_SDES_ECB(plaintext, key):
    if not isinstance(plaintext, str):
        print('Error (e_SDES_ECB): Invalid input')
        return ''

    if len(plaintext) == 0:
        print('Error (e_SDES_ECB): Invalid input')
        return ''

    if get_SDES_value('encoding_type') == '' or get_SDES_value('block_size') == '' or get_SDES_value('key_size') == '' or get_SDES_value('rounds') == '':
        print('Error (e_SDES_ECB): Invalid configuration')
        return ''

    key_size = int(get_SDES_value('key_size'))
    if key == '':
        key = generate_key_SDES()

    if len(key) != key_size:
        print('Error (e_SDES_ECB): Invalid key')
        return ''

    block_size = int(get_SDES_value('block_size'))
    rounds = int(get_SDES_value('rounds'))
    undefined = utilities.get_undefined(plaintext, utilities.get_B6Code())
    modified_plaintext = utilities.remove_undefined(
        plaintext, utilities.get_B6Code())
    modified_plaintext += 'Q' * \
        ((block_size // 6 - (len(modified_plaintext) %
                             (block_size // 6))) % (block_size // 6))
    plain_bin = ''.join(map(lambda c: encode(c, 'B6'), modified_plaintext))
    blocks = [plain_bin[i:i + block_size]
              for i in range(0, len(plain_bin), block_size)]

    for i in range(rounds):
        ki = get_subKey(key, i + 1)
        blocks = list(map(lambda x: feistel(x, ki), blocks))

    blocks = list(map(lambda x: x[block_size//2:] + x[:block_size//2], blocks))
    modified_ciphertext = ''.join(map(lambda c: decode(c, 'B6'), [''.join(
        blocks)[i:i + 6] for i in range(0, len(''.join(blocks)), 6)]))
    ciphertext = utilities.insert_undefinedList(modified_ciphertext, undefined)
    return ciphertext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str)
# Return:       plaintext (str)
# Description:  Decryption using Simple DES
# -----------------------------------------------------------
def d_SDES_ECB(ciphertext, key):
    if not isinstance(ciphertext, str):
        print('Error (d_SDES_ECB): Invalid input')
        return ''

    if len(ciphertext) == 0:
        print('Error (d_SDES_ECB): Invalid input')
        return ''

    if get_SDES_value('encoding_type') == '' or get_SDES_value('block_size') == '' or get_SDES_value('key_size') == '' or get_SDES_value('rounds') == '':
        print('Error (d_SDES_ECB): Invalid configuration')
        return ''

    key_size = int(get_SDES_value('key_size'))
    if key == '':
        key = generate_key_SDES()

    if len(key) != key_size:
        print('Error (d_SDES_ECB): Invalid key')
        return ''

    block_size = int(get_SDES_value('block_size'))
    rounds = int(get_SDES_value('rounds'))
    undefined = utilities.get_undefined(ciphertext, utilities.get_B6Code())
    modified_ciphertext = utilities.remove_undefined(
        ciphertext, utilities.get_B6Code())
    cipher_bin = ''.join(map(lambda c: encode(c, 'B6'), modified_ciphertext))
    blocks = [cipher_bin[i:i + block_size]
              for i in range(0, len(cipher_bin), block_size)]

    for i in reversed(range(rounds)):
        ki = get_subKey(key, i + 1)
        blocks = list(map(lambda x: feistel(x, ki), blocks))

    blocks = list(
        map(lambda x: x[block_size//2:] + x[:block_size // 2], blocks))
    modified_plaintext = ''.join(map(lambda c: decode(c, 'B6'), [''.join(
        blocks)[i:i + 6] for i in range(0, len(''.join(blocks)), 6)]))
    plaintext_list = list(utilities.insert_undefinedList(
        modified_plaintext, undefined))

    count = 0
    while plaintext_list and plaintext_list[-1] == 'Q' and count < block_size // 6:
        plaintext_list.pop()
        count += 1
    plaintext = ''.join(plaintext_list)
    return plaintext


# -----------------------------------------------------------
# Parameters:   block_size (str)
# Return:       result (str)
# Description:  Gets the initial vector
# -----------------------------------------------------------
def get_IV():
    result = blum(643, 131, int(get_SDES_value('block_size')))
    return result

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str)
# Return:       ciphertext (str)
# Description:  Encryption using Simple DES
# -----------------------------------------------------------


def e_SDES_CBC(plaintext, key):
    if not isinstance(plaintext, str):
        print('Error (e_SDES_CBC): Invalid input')
        return ''

    if len(plaintext) == 0:
        print('Error (e_SDES_CBC): Invalid input')
        return ''

    if get_SDES_value('encoding_type') == '' or get_SDES_value('block_size') == '' or get_SDES_value('key_size') == '' or get_SDES_value('rounds') == '':
        print('Error (e_SDES_CBC): Invalid configuration')
        return ''

    key_size = int(get_SDES_value('key_size'))
    if key == '':
        key = generate_key_SDES()

    if len(key) != key_size:
        print('Error (e_SDES): Invalid key')
        return ''

    block_size = int(get_SDES_value('block_size'))
    rounds = int(get_SDES_value('rounds'))
    undefined = utilities.get_undefined(plaintext, utilities.get_B6Code())
    modified_plaintext = utilities.remove_undefined(
        plaintext, utilities.get_B6Code())
    modified_plaintext += 'Q' * \
        ((block_size // 6 - (len(modified_plaintext) %
                             (block_size // 6))) % (block_size // 6))
    plain_bin = ''.join(map(lambda c: encode(c, 'B6'), modified_plaintext))
    blocks = [plain_bin[i:i + block_size]
              for i in range(0, len(plain_bin), block_size)]

    cipher_bin = ''
    iv = get_IV()
    for block in blocks:
        block = utilities.xor(block, iv)
        for i in range(rounds):
            block = feistel(block, get_subKey(key, i+1))
        block = block[block_size // 2:] + block[:block_size // 2]
        cipher_bin += block
        iv = block

    blocks = []
    for i in range(0, len(cipher_bin), 6):
        blocks.append(cipher_bin[i: i + 6])

    while len(blocks[-1]) != 6:
        blocks[-1] += '0'

    ciphertext = ''
    for block in blocks:
        ciphertext += decode_B6(block)
    ciphertext = utilities.insert_undefinedList(ciphertext, undefined)

    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str)
# Return:       plaintext (str)
# Description:  Decryption using Simple DES
# -----------------------------------------------------------


def d_SDES_CBC(ciphertext, key):
    if not isinstance(ciphertext, str):
        print('Error (d_SDES_CBC): Invalid input')
        return ''

    if len(ciphertext) == 0:
        print('Error (d_SDES_CBC): Invalid input')
        return ''

    if get_SDES_value('encoding_type') == '' or get_SDES_value('block_size') == '' or get_SDES_value('key_size') == '' or get_SDES_value('rounds') == '':
        print('Error (d_SDES_CBC): Invalid configuration')
        return ''

    key_size = int(get_SDES_value('key_size'))
    if key == '':
        key = generate_key_SDES()

    if len(key) != key_size:
        print('Error (d_SDES): Invalid key')
        return ''

    block_size = int(get_SDES_value('block_size'))
    rounds = int(get_SDES_value('rounds'))
    undefined = utilities.get_undefined(ciphertext, utilities.get_B6Code())
    modified_ciphertext = utilities.remove_undefined(
        ciphertext, utilities.get_B6Code())
    cipher_bin = ''.join(map(lambda c: encode(c, 'B6'), modified_ciphertext))
    blocks = [cipher_bin[i:i + block_size]
              for i in range(0, len(cipher_bin), block_size)]

    plain_bin = ''
    iv = get_IV()
    for block in blocks:
        temp = block
        for i in range(rounds):
            block = feistel(block, get_subKey(key, rounds - i))
        block = block[block_size // 2:] + block[:block_size // 2]
        block = utilities.xor(block, iv)
        iv = temp
        plain_bin += block

    blocks = []
    for i in range(0, len(plain_bin), 6):
        blocks.append(plain_bin[i: i + 6])

    while len(blocks[-1]) != 6:
        blocks[-1] += '0'

    plaintext = ''
    for block in blocks:
        plaintext += decode_B6(block)
    plaintext = utilities.insert_undefinedList(plaintext, undefined)

    plaintext = plaintext.strip('Q')
    plaintext = plaintext.strip('0')

    return plaintext

# -----------------------------------------
# Parametes:    plaintext (str)
#               key: (shiftString,shifts)
# Return:       ciphertext (str)
# Description:  Encryption using Xshift Cipher
# -----------------------------------------


def e_xshift(plaintext, key):
    # your code here
    ciphertext = ''
    combine = key[0]
    combine_2 = utilities.shift_string(str(combine), key[1], 'l')

    for char in plaintext:
        if char.isalpha():
            i = combine.index(char)
            new_char = combine_2[i]
            ciphertext += new_char
        else:
            ciphertext += char
    return ciphertext

# -----------------------------------------
# Parametes:    ciphertext (str)
#               key: (shiftString,shifts)
# Return:       plaintext (str)
# Description:  Decryption using Xshift Cipher
# -----------------------------------------


def d_xshift(ciphertext, key):
    # your code here
    plaintext = ''
    combine = key[0]
    combine_2 = utilities.shift_string(str(combine), key[1], 'l')

    for char in ciphertext:
        if char.isalpha():
            i = combine_2.index(char)
            new_char = combine[i]
            plaintext += new_char
        else:
            plaintext += char
    return plaintext

# -----------------------------------------
# Parametes:    ciphertext (str)
# Return:       key,plaintext
# Description:  Cryptanalysis of  Xshift Cipher
# -----------------------------------------


def cryptanalysis_xshift(ciphertext):
    alphabet_lower = utilities.get_alphabet()
    alphabet_upper = utilities.get_alphabet().upper()

    alphabet_reversed_lower = utilities.get_alphabet_reversed()
    alphabet_reversed_upper = utilities.get_alphabet_reversed().upper()
    combined = alphabet_lower + alphabet_upper

    mostOccuringChar = utilities.getMaxOccuringChar(ciphertext, combined)

    alpha_case1 = alphabet_lower + alphabet_upper
    alpha_case2 = alphabet_reversed_lower + alphabet_reversed_upper
    alpha_case3 = alphabet_lower + alphabet_reversed_upper
    alpha_case4 = alphabet_reversed_lower + alphabet_upper

    key_1 = combined.index(alpha_case1[mostOccuringChar]) - 4
    key_2 = combined.index(alpha_case2[mostOccuringChar]) - 4
    key_3 = combined.index(alpha_case3[mostOccuringChar]) - 4
    key_4 = combined.index(alpha_case4[mostOccuringChar]) - 4

    decrypt_trial_1 = d_xshift(ciphertext, (alpha_case1, key_1))

    if utilities.is_plaintext(decrypt_trial_1, 'engmix.txt', 0.9):
        key = (alpha_case1, key_1)

    decrypt_trial_2 = d_xshift(ciphertext, (alpha_case2, key_2))

    if utilities.is_plaintext(decrypt_trial_2, 'engmix.txt', 0.9):
        key = (alpha_case2, key_2)

    decrypt_trial_3 = d_xshift(ciphertext, (alpha_case3, key_3))

    if utilities.is_plaintext(decrypt_trial_3, 'engmix.txt', 0.9):
        key = (alpha_case3, key_3)

    decrypt_trial_4 = d_xshift(ciphertext, (alpha_case4, key_4))

    if utilities.is_plaintext(decrypt_trial_4, 'engmix.txt', 0.9):
        key = (alpha_case4, key_4)

    plaintext = d_xshift(ciphertext, key)
    return key, plaintext

# --------------------------------------------
# Parameters: plaintext (string)
#      key (string)
# Return: ciphertext(string)
# Description: Encryption using Atbash cipher
#               There is no key (None)
# ---------------------------------------------


def e_atbash(plaintext, key):
    ciphertext = ""
    alphabet = utilities.get_lower()

    for plainChar in plaintext:
        if plainChar.isalpha():  # if alpha then check if its upper case changing cipher through equation if its upper case
            upperFlag = True if plainChar.isupper() else False
            cipherChar = alphabet[25-alphabet.index(plainChar.lower())]
            ciphertext += cipherChar.upper() if upperFlag else cipherChar
        else:
            ciphertext += plainChar
    return ciphertext

# --------------------------------------------
# Parameters: plaintext (string)
#      key (string)
# Return: ciphertext(string)
# Description: Encryption using Atbash cipher
#               There is no key (None)
# ---------------------------------------------


def e_alberti(plaintext, key):
    ciphertext = ""
    alphabet = utilities.get_lower()

    for plainChar in plaintext:
        if plainChar.isalpha():  # if alpha then check if its upper case changing cipher through equation if its upper case
            upperFlag = True if plainChar.isupper() else False
            cipherChar = alphabet[25-alphabet.index(plainChar.lower())]
            ciphertext += cipherChar.upper() if upperFlag else cipherChar
        else:
            ciphertext += plainChar
    return ciphertext

# -----------------------------------------
# Parametes:    plaintext (str)
#               key: (shiftString,shifts)
# Return:       ciphertext (str)
# Description:  Decryption using Shift Cipher
# -----------------------------------------


def d_shift(ciphertext, key):
    direction = 'l' if key[1] == 'r' else 'r'
    return e_shift(ciphertext, (key[0], direction))

# -----------------------------------------
# Parametes:    plaintext (str)
#               key: (shiftString,shifts)
# Return:       ciphertext (str)
# Description:  Encryption using Shift Cipher
# -----------------------------------------


def e_shift(plaintext, key):
    ciphertext = ''
    shifts, direction = key
    alphabet = utilities.get_lower()

    if shifts < 0:
        shifts *= -1
        direction = 'l' if key[1] == 'r' else 'r'
    shifts = key[0] % 26
    shifts = shifts if key[1] == 'l' else 26 - shifts

    for char in plaintext:
        if char.lower() in alphabet:
            plaintext_index = alphabet.index(char.lower())
            ciphertext_index = (plaintext_index + shifts) % 26
            result = alphabet[ciphertext_index]
            ciphertext += result.upper() if char.isupper() else result
        else:
            ciphertext += char
    return ciphertext

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext (str)
#               key (str)
# Description:  Cryptanalysis of Polybius & Columnar Transposition
# -----------------------------------------------------------


def cryptanalysis_q4A(ciphertext):
    ciphertext = d_polybius(ciphertext, None)
    alphabet = utilities.get_lower()
    dictList = utilities.load_dictionary('engmix.txt')

    for i in range(len(alphabet)):
        for j in range(len(alphabet)):
            key = alphabet[i] + alphabet[j]
            plaintext = d_columnarTrans(ciphertext, key)
            if utilities.is_plaintext(plaintext, dictList, 0.9):
                return plaintext, key

    return '', 'not found'

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext (str)
#               key (str)
#               (x, 'r') (tuple)
# Description:  Cryptanalysis of Shift & Columnar Transposition
# -----------------------------------------------------------


def cryptanalysis_q4B(ciphertext):
    alphabet = utilities.get_lower()
    dictList = utilities.load_dictionary('engmix.txt')

    for x in range(26):
        shift_plaintext = d_shift(ciphertext, (x, 'r'))
        for i in range(len(alphabet)):
            for j in range(len(alphabet)):
                key = alphabet[i] + alphabet[j]
                plaintext = d_columnarTrans(shift_plaintext, key)
                if utilities.is_plaintext(plaintext, dictList, 0.9):
                    return plaintext, key, (x, 'r')

    return '', 'not found', (0, 'r')

# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext (str)
#               key (str)
#               (x, 'r') (tuple)
# Description:  Cryptanalysis of Hill
# -----------------------------------------------------------


def cryptanalysis_q4C(ciphertext):
    alphabet = utilities.get_lower()
    dictList = utilities.load_dictionary('engmix.txt')
    valid_keys = generate_valid_keys_q4C()

    for key in valid_keys:
        plaintext = d_hill(ciphertext, key)
        if utilities.is_plaintext(plaintext, dictList, 0.9):
            return plaintext, key.lower(), (0, 'r')
    return '', 'not found', (0, 'r')

# -----------------------------------------------------------
# Parameters:   N/A
# Return:       valid_keys (list)
# Description:  Generates all possible keys for Hill
# -----------------------------------------------------------


def generate_valid_keys_q4C():
    alphabet_key = 'ABCDE'
    alphabet = utilities.get_lower()
    valid_keys = []
    for i in range(len(alphabet_key)):
        for j in range(len(alphabet_key)):
            for k in range(len(alphabet_key)):
                for l in range(len(alphabet_key)):
                    key = alphabet_key[i] + alphabet_key[j] + \
                        alphabet_key[k] + alphabet_key[l]
                    pos_1 = alphabet_key.index(key[0])
                    pos_2 = alphabet_key.index(key[1])
                    pos_3 = alphabet_key.index(key[2])
                    pos_4 = alphabet_key.index(key[3])
                    key_matrix = [[pos_1, pos_2], [pos_3, pos_4]]
                    key_inv = matrix.inverse(key_matrix, len(alphabet))

                    if not isinstance(key_inv, str):
                        valid_keys.append(key)
    return valid_keys


def isValidKey_mathCipher(key):
    # your code here
    if not isinstance(key[0], str):
        return False

    if len(key[0]) <= 2:
        return False

    if not isinstance(key[1], list):
        return False

    if len(key[1]) != 3:
        return False

    a = key[1][0]
    b = key[1][1]

    if not isinstance(a, int) or not isinstance(b, int):
        return False

    if not mod.has_mul_inv(a, len(key[0])) or not mod.has_mul_inv(b, len(key[0])):
        return False
    return True


def e_mathCipher(plaintext, key):
    # your code here
    if not isValidKey_mathCipher(key):
        print('Error(e_mathCipher): invalid key')
        return ''

    if len(plaintext) == 0:
        print('Error(e_mathCipher): invalid plaintext')
        return ''

    ciphertext = ''
    baseString = key[0]
    a = key[1][0]
    b = key[1][1]
    c = key[1][2]

    for char in plaintext:
        if char.lower() in baseString:
            index = baseString.index(char.lower())
            result = b * (a * index + b) - c
            if result > len(baseString):
                result %= len(baseString)
            if char.isupper():
                ciphertext += baseString[result].upper()
            else:
                ciphertext += baseString[result]
        else:
            ciphertext += char

    return ciphertext


def d_mathCipher(ciphertext, key):
    # your code here
    if not isValidKey_mathCipher(key):
        print('Error(d_mathCipher): invalid key')
        return ''

    if len(ciphertext) == 0:
        print('Error(d_mathCipher): invalid ciphertext')
        return ''

    plaintext = ''
    baseString = key[0]
    a = key[1][0]
    b = key[1][1]
    c = key[1][2]

    for char in ciphertext:
        if char.lower() in baseString:
            index = baseString.index(char.lower())
            a_inv = mod.mul_inv(a, len(baseString))
            b_inv = mod.mul_inv(b, len(baseString))
            result = (a_inv * (b_inv * ((index + c) %
                                        len(baseString)) - b)) % len(baseString)

            if char.isupper():
                plaintext += baseString[result].upper()
            else:
                plaintext += baseString[result]
        else:
            plaintext += char
    return plaintext


def analyze_mathCipher(baseString):
    # your code here
    total = len(baseString) ** 3
    valid = 0
    illegal = 0
    noCipher = 0
    decimation = 0

    for a in range(len(baseString)):
        if not mod.has_mul_inv(a, len(baseString)):
            illegal += len(baseString) ** 2
        else:
            for b in range(len(baseString)):
                if not mod.has_mul_inv(b, len(baseString)):
                    illegal += len(baseString)
                else:
                    for c in range(len(baseString)):
                        if (b * (a + b) - c) % len(baseString) == 1:
                            noCipher += 1
                        elif (b * (a + b) - c) % len(baseString) == a:
                            decimation += 1
                        else:
                            valid += 1
    noCipher -= decimation
    valid = total - illegal - noCipher - decimation
    return [total, illegal, noCipher, decimation, valid]


def stats_mathCipher():
    all_avg, all_best, all_worst, all_count = 0, 1, 0, 0
    prime_avg, prime_best, prime_worst, prime_count = 0, 1, 0, 0
    non_prime_avg, non_prime_best, non_prime_worst, non_prime_count = 0, 1, 0, 0

    i = 2
    while i < 101:
        analysis = analyze_mathCipher('0' * i)
        valid_ratio = float(analysis[4]) / float(analysis[0])
        all_avg += valid_ratio

        if (valid_ratio < all_best):
            all_best = valid_ratio
        if(valid_ratio > all_worst):
            all_worst = valid_ratio

        if (mod.is_prime(i)):
            prime_avg += valid_ratio
            if (valid_ratio < prime_best):
                prime_best = valid_ratio
            if(valid_ratio > prime_worst):
                prime_worst = valid_ratio
            prime_count += 1
        else:
            non_prime_avg += valid_ratio
            if (valid_ratio < non_prime_best):
                non_prime_best = valid_ratio
            if(valid_ratio > non_prime_worst):
                non_prime_worst = valid_ratio
            non_prime_count += 1
        all_count += 1
        i += 1

    print('For all numbers:')
    print('\tAverage = {0:.2f}%'.format(all_avg / all_count * 100))
    print('\tBest = {0:.2f}%'.format(all_best * 100))
    print('\tWorst = {0:.2f}%'.format(all_worst * 100))
    print('For Primes:')
    print('\tAverage = {0:.2f}%'.format(prime_avg / prime_count * 100))
    print('\tBest = {0:.2f}%'.format(prime_best * 100))
    print('\tWorst = {0:.2f}%'.format(prime_worst * 100))
    print('For non Primes:')
    print('\tAverage = {0:.2f}%'.format(non_prime_avg / non_prime_count * 100))
    print('\tBest = {0:.2f}%'.format(non_prime_best * 100))
    print('\tWorst = {0:.2f}%'.format(non_prime_worst * 100))
    return


def cryptanalysis_mathCipher(ciphertext):
    # your code here
    baseString = utilities.get_baseString()
    string_length = len(utilities.get_lower())
    dictList = utilities.load_dictionary('engmix.txt')
    plaintext = ''
    count = 0

    while string_length < len(baseString):
        for i in range(string_length):
            if mod.has_mul_inv(i, string_length):
                for j in range(string_length):
                    if mod.has_mul_inv(j, string_length):
                        for k in range(string_length):
                            key = (baseString[:string_length], [i, j, k])
                            if isValidKey_mathCipher(key) and (j * (i + j) - k) % len(baseString) != 1 and (j * (i + j) - k) % len(baseString) != i:
                                count += 1
                                plaintext = d_mathCipher(ciphertext, key)
                                if utilities.is_plaintext(plaintext, dictList, 0.9):
                                    print("key found after", count, "attempts")
                                    return plaintext, key
        string_length += 1
    return '', 'not found'


def LRM(b, e, m):
    # your code here
    base = b % m
    x = base
    e_binary = bin(e)[2:]
    for i in e_binary[1:]:
        base = (base * base) % m
        if i == "1":
            base = (x * base) % m
    return base
