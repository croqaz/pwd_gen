
# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import re, math
import string
import binascii as ba
import base64
import json
import bz2, zlib

from Padding import appendPadding, removePadding
from pbkdf2 import PBKDF2

from Crypto.Cipher import AES
from Crypto.Cipher import ARC2
from Crypto.Cipher import CAST
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

#
ROT = string.maketrans('nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
#
SCRAMBLE = ['None', 'ROT13', 'ZLIB', 'BZ2']
SCRAMBLE_D = {'None':'N', 'ROT13':'R', 'ZLIB':'ZL', 'BZ2':'BZ'}
ENC = {'AES':'AES', 'Blowfish':'B', 'ARC2':'ARC', 'CAST':'CA', 'DES3':'D', 'RSA':'RSA', 'None':'N'}
ENCODE = ['Base64 Codec', 'Base32 Codec', 'HEX Codec', 'Quopri Codec', 'String Escape', 'UU Codec', 'Json', 'XML']
ENCODE_D = {'Base64 Codec':'64', 'Base64':'64', 'Base32 Codec':'32', 'Base32':'32',
    'HEX Codec':'H', 'HEX':'H', 'Quopri Codec':'Q', 'Quopri':'Q',
    'String Escape':'STR', 'String esc':'STR',
    'UU Codec':'UU', 'Json':'JS', 'XML':'XML'}
#
NO_TAGS = re.compile(
    '<#>(?P<ts>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})</?#>|' \
    '\[#\](?P<tq>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\[#\]|' \
    '\{#\}(?P<ta>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\{#\}|' \
    '\(#\)(?P<tp>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\(#\)|' \
    '(?P<tx><pre>[0-9a-zA-Z ]{1,3}</pre>\s*?<enc>[0-9a-zA-Z ]{1,3}</enc>\s*?<post>[0-9a-zA-Z ]{1,3}</post>)|' \
    '(?P<tj>"pre": "[0-9a-zA-Z ]{1,3}",\s*?"enc": "[0-9a-zA-Z ]{1,3}",\s*?"post": "[0-9a-zA-Z ]{1,3}")')
#
# These numbers are used when (re)creating PNG images.
SCRAMBLE_NR = {'None':'1', 'ROT13':'2', 'ZLIB':'3', 'BZ2':'4'}
ENCRYPT_NR = {'AES':'1', 'ARC2':'2', 'CAST':'3', 'Blowfish':'5', 'DES3':'4', 'RSA':'6', 'None':'9'}
ENCODE_NR = {'Base64 Codec':'4', 'Base32 Codec':'2', 'HEX Codec':'1', 'Quopri Codec':'9', 'String Escape':'6', 'UU Codec':'8', 'XML':'7'}
#

def findg(g):
    for i in g:
        if i: return ''.join(i.split())

#

class ScrambledEgg():

    def __init__(self):
        self.error = '' # Error string.
        self.pre = ''   # Current operations, in order.
        self.enc = ''
        self.post = ''
        self.rsaFillChar = unichr(2662).encode('utf_8')
        self.rsa_path = ''

    def __error(self, step, pre, enc, post, field='R'):
        #
        if step==1:
            if field=='R':
                pre += ' (ERROR!)'
            else:
                pre += ' (IGNORED!)'
        elif step==2:
            enc += ' (ERROR!)'
        elif step==3:
            post += ' (ERROR!)'
        #
        if field=='R':
            self.error = '  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        else:
            self.error = '  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        #

    def _fix_password(self, pwd, enc):
        '''
        Scramble and adapt the password for each encryption. \n\
        AES accepts maxim 32 characters. \n\
        ARC2 accepts maxim 128 characters. \n\
        CAST accepts maxim 8 characters. \n\
        Blowfish accepts maxim 56 characters. \n\
        DES3 accepts maxim 24 characters.
        '''
        #
        # Accepting ANY type of password.
        pwd = ba.b2a_base64(pwd)

        if enc == 'AES' or enc == ENC['AES']:
            key_size = 32

        elif enc == 'Blowfish' or enc == ENC['Blowfish']:
            key_size = 56

        elif enc == 'ARC2' or enc == ENC['ARC2']:
            key_size = 128

        elif enc == 'CAST' or enc == ENC['CAST']:
            key_size = 8

        elif enc == 'DES3' or enc == ENC['DES3']:
            key_size = 24

        elif enc == 'RSA' and self.rsa_path:
            key_size = 56
            # Read the public/ private key from file, encrypt password and return.
            rsa_key = open(self.rsa_path, 'rb').read()
            o = RSA.importKey(rsa_key)
            # RSA text is max 128 characters.
            rsa_pwd = pwd[:128]
            pwd = o.encrypt(rsa_pwd, 0)[0]
            del o, rsa_key, rsa_pwd

        elif not enc or enc == 'None':
            return pwd

        else:
            raise Exception('Fix password: Invalid encryption mode "%s" !' % enc)

        if not pwd:
            # Only for NULL passwords.
            return key_size * 'X'

        # Scramble the password many times.
        # Can't use random salt, 'cose the same pass must be recreated for decryption.
        hash_key = PBKDF2(passphrase=pwd, salt='scregg', iterations=1024)

        # The password for encryption/ decryption.
        # This is very strong, binary data!
        return hash_key.read(key_size)
        #

    def encrypt(self, txt, pre, enc, post, pwd, tags=True):
        #
        # Scramble operation.
        if not pre or pre == 'None':
            pre = 'None'
        elif pre == 'ZLIB':
            txt = zlib.compress(txt)
        elif pre == 'BZ2':
            txt = bz2.compress(txt)
        elif pre == 'ROT13':
            txt = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % pre)
        #
        # Check RSA key path.
        if enc == 'RSA' and not os.path.exists(self.rsa_path):
            print 'RSA encryption must specify a valid path !'
            self.__error(2, pre, enc, post, field='L')
            return
        #
        pwd = self._fix_password(pwd, enc)
        txt = appendPadding(txt, blocksize=16)
        # Encryption operation.
        if enc == 'AES':
            o = AES.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'ARC2':
            o = ARC2.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'CAST':
            o = CAST.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'Blowfish':
            o = Blowfish.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'DES3':
            o = DES3.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'RSA':
            # Using Blowfish encryption for RSA.
            o = Blowfish.new(pwd, mode=3)
            encrypted = o.encrypt(txt)
        elif not enc or enc == 'None':
            enc = 'None'
            encrypted = txt
        else:
            raise Exception('Invalid encryption mode "%s" !' % enc)
        #
        # Codec operation.
        if post == 'Base64' or post == 'Base64 Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_base64(encrypted))
            else:
                final = ba.b2a_base64(encrypted)
        elif post == 'Base32' or post == 'Base32 Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), base64.b32encode(encrypted))
            else:
                final = base64.b32encode(encrypted)
        elif post == 'HEX' or post == 'HEX Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_hex(encrypted))
            else:
                final = ba.b2a_hex(encrypted)
        elif post == 'Quopri' or post == 'Quopri Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_qp(encrypted, quotetabs=True, header=True))
            else:
                final = ba.b2a_qp(encrypted, quotetabs=True, header=True)
        elif post == 'String esc' or post == 'String Escape':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], encrypted.encode('string_escape'))
            else:
                final = encrypted.encode('string_escape')
        elif post == 'UU Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), encrypted.encode('uu'))
            else:
                final = encrypted.encode('uu')
        elif post == 'Json':
            if tags:
                # Format : {"pre": "AAA", "enc": "BBB", "post": "CCC", "data": "Blah blah blah"}
                final = '{"pre": "%s", "enc": "%s", "post": "%s", "data": "%s"}' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], ba.b2a_base64(encrypted).strip())
            else:
                final = json.dumps({'data':ba.b2a_base64(encrypted).strip()})
        elif post == 'XML':
            if tags:
                # Format : <root><pre>AAA</pre> <enc>BBB</enc> <post>CCC</post> <data>Blah blah blah</data></root>
                final = '<root>\n<pre>%s</pre><enc>%s</enc><post>%s</post>\n<data>%s</data>\n</root>' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], ba.b2a_base64(encrypted).strip())
            else:
                final = '<root>\n<data>%s</data>\n</root>' % ba.b2a_base64(encrypted).strip()
        else:
            raise Exception('Invalid codec "%s" !' % post)
        #
        return final
        #

    def decrypt(self, txt, pre, enc, post, pwd):
        #
        # Trying to identify and/or delete pre/enc/post tags.
        try:
            re_groups = re.search(NO_TAGS, txt).groups()
            tags = findg(re_groups)

            # If Json.
            if tags.startswith('"pre"'):
                pre = 'Json'
                enc = re.search('"enc":"([0-9a-zA-Z ]{1,3})"', tags).group(1)
                post = re.search('"pre":"([0-9a-zA-Z ]{1,3})"', tags).group(1)
                txt = re.search('"data":\s*"(.+?)"', txt, re.S).group(1)

            # If XML.
            elif tags.startswith('<pre>'):
                pre = 'XML'
                enc = re.search('<enc>([0-9a-zA-Z ]{1,3})</enc>', tags).group(1)
                post = re.search('<pre>([0-9a-zA-Z ]{1,3})</pre>', tags).group(1)
                txt = re.search('<data>(.+)</data>', txt, re.S).group(1)

            else:
                pre = tags.split(':')[2]
                enc = tags.split(':')[1]
                post = tags.split(':')[0]
                txt = re.sub(NO_TAGS, '', txt)

            self.pre = pre
            self.enc = enc
            self.post = post
        except:
            pass
        #
        # Check RSA key path.
        if enc == 'RSA' and not os.path.exists(self.rsa_path):
            print 'RSA decryption must specify a valid path !'
            self.__error(2, pre, enc, post)
            return
        #
        # Adapting password for encryption.
        pwd = self._fix_password(pwd, enc)
        #
        # Codec operation.
        if not pre:
            self.__error(1, 'None', enc, post) ; return
        elif pre == 'Base64 Codec' or pre == ENCODE_D['Base64 Codec']:
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Base32 Codec' or pre == ENCODE_D['Base32 Codec']:
            try: txt = base64.b32decode(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'HEX Codec' or pre == ENCODE_D['HEX Codec']:
            try: txt = ba.a2b_hex(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Quopri Codec' or pre == ENCODE_D['Quopri Codec']:
            try: txt = ba.a2b_qp(txt, header=True)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'String Escape' or pre == ENCODE_D['String Escape']:
            try: txt = txt.decode('string_escape')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'UU Codec' or pre == ENCODE_D['UU Codec']:
            try: txt = txt.decode('uu')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Json' or pre == ENCODE_D['Json']:
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'XML':
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        else:
            raise Exception('Invalid codec "%s" !' % pre)
        #
        # Decryption operation.
        if enc == 'AES' or enc == ENC['AES']:
            o = AES.new(pwd, mode=2)
        elif enc == 'ARC2' or enc == ENC['ARC2']:
            o = ARC2.new(pwd, mode=2)
        elif enc == 'CAST' or enc == ENC['CAST']:
            o = CAST.new(pwd, mode=2)
        elif enc == 'Blowfish' or enc == ENC['Blowfish']:
            o = Blowfish.new(pwd, mode=2)
        elif enc == 'DES3' or enc == ENC['DES3']:
            o = DES3.new(pwd, mode=2)
        elif enc == 'RSA':
            # Using Blowfish decryption for RSA.
            o = Blowfish.new(pwd, mode=3)
        elif not enc or enc == 'None':
            txt = removePadding(txt, 16)
        else:
            raise Exception('Invalid decrypt "%s" !' % enc)
        #
        if enc != 'None':
            try: txt = removePadding(o.decrypt(txt), 16)
            except: self.__error(2, pre, enc, post) ; return
        #
        # Un-scramble operation.
        if not post or post == 'N' or post == 'None':
            final = txt
        elif post == 'ZLIB' or post == SCRAMBLE_D['ZLIB']:
            try: final = zlib.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'BZ2' or post == SCRAMBLE_D['BZ2']:
            try: final = bz2.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'ROT13' or post == SCRAMBLE_D['ROT13']:
            final = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % post)
        #
        return final
        #

    def toImage(self, txt, pre, enc, post, pwd, path, encrypt=True):
        '''
        Any information, text and/or files, can be encoded inside a little PNG image. \n\
        Depending on how you encode the crypted data, images come in 3 flavors: HEX, Base32 and Base64. \n\
        Normally each letter can be transformed into a color from 1 to 255 ; so 4 colors become one pixel. \n\
        HEX encoding is `high density`. Two letters are transformed into a color from 1 to 255,
        so one pixel consists of 8 letters, instead of 4 letters.
        '''
        #
        # Input can be string, or file. If's file, read it.
        if str(type(txt)) == "<type 'file'>":
            txt.seek(0)
            txt = txt.read()

        # Strip pre/enc/post tags.
        txt = re.sub(NO_TAGS, '', txt)

        # All text must be reversed, to pop from the end of the characters list.
        if encrypt: # If text MUST be encrypted first, encrypt without pre/enc/post tags.
            val = self.encrypt(txt, pre, enc, post, pwd, False)[::-1]
            if not val:
                return
        else: # Else, the text is already encrypted.
            val = txt[::-1]

        # Calculate the edge of the square and blank square.
        if post == 'HEX Codec':
            # Length.
            edge = math.ceil(math.sqrt( float(len(val) + 1)/8.0 ))
            blank = math.ceil(edge * edge - float(len(val)) / 8.0)
            if blank:
                blank -= 1
        else:
            # Length + 5, just to make sure there are enough blank pixels.
            edge = math.ceil(math.sqrt( float(len(val) + 5)/4.0 ))
            blank = math.ceil((edge * edge - float(len(val))/4.0) / 2.0)

        # `Second pixel` : a number representing the length of valid characters.
        # This is only used for HEX, because when decrypting, this number of letters is trimmed from the end of the string.
        if post == 'HEX Codec':
            second_pixel = str(QtGui.QColor(int(blank)).name())[3:]
            val += second_pixel[::-1]
            #print '! Second pixel', second_pixel
            del second_pixel

        # `First pixel` : a string with 4 numbers representing Pre/ Enc/ Post information.
        # For Base64/ Base32, this variabile is encoded in one pixel (4 characters).
        # For HEX, First Pixel + Second Pixel are both encoded in one pixel (8 characters).
        if post == 'HEX Codec':
            first_pixel = '0'
        else:
            first_pixel = '1'

        # Add first pixel at the end of the reversed string.
        first_pixel += SCRAMBLE_NR[pre] + ENCRYPT_NR[enc] + ENCODE_NR[post]
        val += first_pixel[::-1]
        #print '! First pixel', first_pixel
        del first_pixel

        # Explode the encrypted string.
        list_val = list(val)
        # Creating new square image.
        print('Creating img, %ix%i, blank : %i, string to encode : %i chars.' % (edge, edge, blank, len(val)))
        im = QtGui.QImage(edge, edge, QtGui.QImage.Format_ARGB32)
        _pix = im.setPixel
        _rgba = QtGui.qRgba
        _int = int
        _ord = ord

        # HEX codec.
        if post == 'HEX Codec':
            for i in range(int(edge)):
                for j in range(int(edge)):
                    #
                    _r = _g = _b = _a = 255

                    # Red
                    if len(list_val) >= 2:
                        _r = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _r = _int(list_val.pop(), 16)

                    # Green
                    if len(list_val) >= 2:
                        _g = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _g = _int(list_val.pop(), 16)

                    # Blue
                    if len(list_val) >= 2:
                        _b = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _b = _int(list_val.pop(), 16)

                    # Alpha
                    if len(list_val) >= 2:
                        _a = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _a = _int(list_val.pop(), 16)
                    #
                    _pix(j, i, _rgba(_r, _g, _b, _a))
                    #

        # Base 64 and Base 32.
        else:
            for i in range(int(edge)):
                for j in range(int(edge)):
                    #
                    if blank:
                        blank -= 1
                        _pix(j, i, _rgba(255, 255, 255, 255))
                        continue
                    #
                    _r = _g = _b = _a = 255

                    if len(list_val) >= 1:
                        _r = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _g = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _b = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _a = _ord(list_val.pop())

                    _pix(j, i, _rgba(_r, _g, _b, _a))
                    #

        #
        try:
            im.save(path, 'PNG', -1)
        except:
            print('Cannot save PNG file "%s" !' % path)
        #

    def fromImage(self, pwd, path, decrypt=True):
        #
        if not os.path.isfile(path):
            print('Cannot find file "%s" !' % path)
            return
        #
        try:
            im = QtGui.QImage()
            im.load(path, 'PNG')
        except:
            print('Image "%s" is not a valid RGBA PNG !' % path)
            return

        list_val = []
        _pix = im.pixel
        _r = QtGui.qRed
        _g = QtGui.qGreen
        _b = QtGui.qBlue
        _a = QtGui.qAlpha

        fp_val = 0

        # Calculate First Pixel.
        for i in range(im.width()):
            for j in range(im.height()):
                #
                if fp_val:
                    break
                #
                pix1 = _pix(j, i)
                #
                if pix1 != 4294967295L: # Color #FFFFFFFF, completely white pixel.
                    fp_val = [_r(pix1), _g(pix1), _b(pix1), _a(pix1)]
                    break
                #

        # Calculate the colors of first pixel.
        # For HEX: Red+Green represents pre/enc/post information and Blue+Alpha value represents nr of valid characters.
        # For Base64/ Base32, first pixel represents only the Pre/ Enc/ Post information.
        cc = QtGui.QColor(fp_val[0], fp_val[1], fp_val[2], fp_val[3])
        first_pixel_hex = cc.name()[1:5]
        first_pixel_b = [chr(fp_val[0]), chr(fp_val[1]), chr(fp_val[2]), chr(fp_val[3])]
        if cc.alpha() < 16:
            blank = int(hex(cc.blue())[2:]+'0'+hex(cc.alpha())[2:], 16)
        else:
            blank = int(hex(cc.blue())[2:]+hex(cc.alpha())[2:], 16)

        # Reverse number dictionaries.
        reverse_s = dict(zip(SCRAMBLE_NR.values(), SCRAMBLE_NR.keys()))
        reverse_ey = dict(zip(ENCRYPT_NR.values(), ENCRYPT_NR.keys()))
        reverse_ed = dict(zip(ENCODE_NR.values(), ENCODE_NR.keys()))

        if first_pixel_hex[0] == '0' and first_pixel_b[0] != '0':
            post = reverse_s[first_pixel_hex[1]]
            enc = reverse_ey[first_pixel_hex[2]]
            pre = reverse_ed[first_pixel_hex[3]]
        else:
            post = reverse_s[first_pixel_b[1]]
            enc = reverse_ey[first_pixel_b[2]]
            pre = reverse_ed[first_pixel_b[3]]

        # Save Pre/ Enc/ Post information for GUI.
        self.pre = pre
        self.enc = enc
        self.post = post

        # For HEX.
        if pre == 'HEX Codec':
            for i in range(im.width()):
                for j in range(im.height()):
                    #
                    rgba = _pix(j, i)
                    #
                    # For each channel in this pixel.
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        if v < 16:
                            list_val.append('0'+hex(v)[-1])
                        else:
                            list_val.append(hex(v)[-2:])
                    #

        # For the rest.
        else:
            for i in range(im.width()):
                for j in range(im.height()):
                    #
                    rgba = _pix(j, i)
                    #
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        if v and v != 255:
                            list_val.append(unichr(v))
                        # If this color is 0 or 255, the rest of the pixel is blank.
                        else:
                            break
                    #

        # Fix `blank` value.
        if blank:
            blank = - blank * 8
        else:
            blank = len(list_val) * 8

        # Used for DEBUG.
        #ff = open('dump.txt', 'wb')
        #ff.write('\nColor: %s ; FP Val: %s ; FP Hex: %s ; FP B64/32: %s ; Blank: %i' % (cc.name(),str(fp_val),first_pixel_hex,''.join(first_pixel_b),blank))
        #ff.write('\n'+''.join(list_val)+'\n')
        #ff.write(''.join(list_val)[8:blank])
        #ff.close() ; del ff, cc, fp_val

        # If the text MUST be decrypted.
        if decrypt:
            if pre == 'HEX Codec':
                val = self.decrypt(''.join(list_val)[8:blank], pre, enc, post, pwd)
            else:
                val = self.decrypt(''.join(list_val[4:]), pre, enc, post, pwd)

            if not val:
                print('Error from image (decrypt)! ' + self.error.strip())
            else:
                return val

        # Else, don't decrypt.
        else:
            if pre == 'HEX Codec':
                val = ''.join(list_val)[8:blank]
            else:
                val = ''.join(list_val[4:])

            if not val:
                print('Error from image (no decrypt)!')
            else:
                return val
        #

    def _import(self, pre, enc, post, pwd, fpath, decrypt=True):
        #
        if not os.path.isfile(fpath):
            print('Cannot find file "%s" !' % fpath)
            return
        #
        ext = os.path.splitext(fpath)[1].lower()
        #
        # For PNG files.
        if ext=='.png':
            return self.fromImage(pwd, fpath, decrypt)
        #
        # For the rest of the files.
        if decrypt:
            val = self.decrypt(open(fpath, 'rb').read(), pre, enc, post, pwd)
            if not val:
                print(self.error)
            else:
                return val
        # Else, don't decrypt.
        else:
            val = open(fpath, 'rb').read()
            return val
        #

#

#
# Eof()
#
