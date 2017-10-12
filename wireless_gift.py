import sys, memecrypto, lzss
from struct import unpack as up, pack as pk
import os

def safe_read(fn):
    try:
        with open(fn, 'rb') as f:
            return f.read()
    except IOError:
        print 'Error: Failed to read %s!' % fn
        sys.exit(1)

def safe_write(fn, data):
    try:
        with open(fn, 'wb') as f:
            f.write(data)
    except IOError:
        print 'Error: Failed to write to %s!' % fn
        sys.exit(1)

def main(argc, argv):
    if argc != 2:
        print 'Usage: %s local_wireless_gift [output]' % argv[0]
        sys.exit(1)
    gift = safe_read(argv[1])

    dec_size, comp_size = up('<II', gift[0x34:0x3C])
    if comp_size >= 0x5000 or dec_size >= 0x5000 or len(gift) != 0x3C + comp_size + 8:
        print 'Error: %s is not a valid wifi gift!' % argv[1]
    enc_gift = gift[0x3C:]

    valid, dec_gift = memecrypto.verify_meme_data(enc_gift, 'local_wireless')
    if not valid:
        print 'Error: %s is not a valid memesigned gift!' % argv[1]
        sys.exit(1)

    dec_gift = lzss.decompress(dec_gift[:-0x8])

    prefix, ext = os.path.splitext(argv[1])

    if len(dec_gift) == 0x310:
        print 'Gift is a single wondercard! Writing...'
        safe_write('%s_dec.wc7full' % prefix, dec_gift)
    elif len(dec_gift) % 0x310 == 0:
        num_cards = len(dec_gift) / 0x310
        print 'Gift is %d wondercards! Writing...' % num_cards
        cards = up('<' + '784s' * num_cards, dec_gift)
        for i, card in enumerate(cards):
            safe_write('%s_dec_%d.wc7full' % (prefix, i), card)
    else:
        print 'Unknown local wireless gift, writing raw...'
        safe_write('%s_dec.%s' % (prefix, ext), dec_gift)
    print 'Done!'
    return 0

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)