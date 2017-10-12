from Crypto.Cipher import AES
from binascii import unhexlify as uhx, hexlify as hx
from struct import unpack as up, pack as pk
import hashlib, sys

public_keys = {
    0x0 : uhx('307C300D06092A864886F70D0101010500036B003068026100B3D68C9B1090F6B1B88ECFA9E2F60E9C62C3033B5B64282F262CD393B433D97BD3DB7EBA470B1A77A3DB3C18A1E7616972229BDAD54FB02A19546C65FA4773AABE9B8C926707E7B7DDE4C867C01C0802985E438656168A4430F3F3B9662D7D010203010001'),
    0x1 : uhx('307C300D06092A864886F70D0101010500036B003068026100C10F4097FD3C781A8FDE101EF3B2F091F82BEE4742324B9206C581766EAF2FBB42C7D60D749B999C529B0E22AD05E0C880231219AD473114EC454380A92898D7A8B54D9432584897D6AFE4860235126190A328DD6525D97B9058D98640B0FA050203010001'),
    0x2 : uhx('307C300D06092A864886F70D0101010500036B003068026100C3C8D89F55D6A236A115C77594D4B318F0A0A0E3252CC0D6345EB9E33A43A5A56DC9D10B7B59C135396159EC4D01DEBC5FB3A4CAE47853E205FE08982DFCC0C39F0557449F97D41FED13B886AEBEEA918F4767E8FBE0494FFF6F6EE3508E3A3F0203010001'),
    0x3 : uhx('307C300D06092A864886F70D0101010500036B003068026100B61E192091F90A8F76A6EAAA9A3CE58C863F39AE253F037816F5975854E07A9A456601E7C94C29759FE155C064EDDFA111443F81EF1A428CF6CD32F9DAC9D48E94CFB3F690120E8E6B9111ADDAF11E7C96208C37C0143FF2BF3D7E831141A9730203010001'),
    0x4 : uhx('307C300D06092A864886F70D0101010500036B003068026100A0F2AC80B408E2E4D58916A1C706BEE7A24758A62CE9B50AF1B31409DFCB382E885AA8BB8C0E4AD1BCF6FF64FB3037757D2BEA10E4FE9007C850FFDCF70D2AFAA4C53FAFE38A9917D467862F50FE375927ECFEF433E61BF817A645FA5665D9CF0203010001'),
    0x5 : uhx('307C300D06092A864886F70D0101010500036B003068026100D046F2872868A5089205B226DE13D86DA552646AC152C84615BE8E0A5897C3EA45871028F451860EA226D53B68DDD5A77D1AD82FAF857EA52CF7933112EEC367A06C0761E580D3D70B6B9C837BAA3F16D1FF7AA20D87A2A5E2BCC6E383BF12D50203010001'),
    0x6 : uhx('307C300D06092A864886F70D0101010500036B003068026100D379919001D7FF40AC59DF475CF6C6368B1958DD4E870DFD1CE11218D5EA9D88DD7AD530E2806B0B092C02E25DB092518908EDA574A0968D49B0503954B24284FA75445A074CE6E1ABCEC8FD01DAA0D21A0DD97B417BC3E54BEB7253FC06D3F30203010001'),
    0x7 : uhx('307C300D06092A864886F70D0101010500036B003068026100B751CB7D282625F2961A7138650ABE1A6AA80D69548BA3AE9DFF065B2805EB3675D960C62096C2835B1DF1C290FC19411944AFDF3458E3B1BC81A98C3F3E95D0EE0C20A0259E614399404354D90F0C69111A4E525F425FBB31A38B8C558F23730203010001'),
    0x8 : uhx('307C300D06092A864886F70D0101010500036B003068026100B328FE4CC41627882B04FBA0A396A15285A8564B6112C1203048766D827E8E4E5655D44B266B2836575AE68C8301632A3E58B1F4362131E97B0AA0AFC38F2F7690CBD4F3F4652072BFD8E9421D2BEEF177873CD7D08B6C0D1022109CA3ED5B630203010001'),
    0x9 : uhx('307C300D06092A864886F70D0101010500036B003068026100C4B32FD1161CC30D04BD569F409E878AA2815C91DD009A5AE8BFDAEA7D116BF24966BF10FCC0014B258DFEF6614E55FB6DAB2357CD6DF5B63A5F059F724469C0178D83F88F45048982EAE7A7CC249F84667FC393684DA5EFE1856EB10027D1D70203010001'),
    0xA : uhx('307C300D06092A864886F70D0101010500036B003068026100C5B75401E83352A64EEC8916C4206F17EC338A24A6F7FD515260696D7228496ABC1423E1FF30514149FC199720E95E682539892E510B239A8C7A413DE4EEE74594F073815E9B434711F6807E8B9E7C10C281F89CF3B1C14E3F0ADF83A2805F090203010001'),
    0xB : uhx('307C300D06092A864886F70D0101010500036B003068026100AC36B88D00C399C660B4846287FFC7F9DF5C07487EAAE3CD4EFD0029D3B86ED3658AD7DEE4C7F5DA25F9F6008885F343122274994CAB647776F0ADCFBA1E0ECEC8BF57CAAB8488BDD59A55195A0167C7D2C4A9CF679D0EFF4A62B5C8568E09770203010001'),
    0xC : uhx('307C300D06092A864886F70D0101010500036B003068026100CAC0514D4B6A3F70771C461B01BDE3B6D47A0ADA078074DDA50703D8CC28089379DA64FB3A34AD3435D24F7331383BDADC4877662EFB555DA2077619B70AB0342EBE6EE888EBF3CF4B7E8BCCA95C61E993BDD6104C10D11115DC84178A5894350203010001'),
    0xD : uhx('307C300D06092A864886F70D0101010500036B003068026100B906466740F5A9428DA84B418C7FA6146F7E24C783373D671F9214B40948A4A317C1A4460111B45D2DADD093815401573E52F0178890D35CBD95712EFAAE0D20AD47187648775CD9569431B1FC3C784113E3A48436D30B2CD162218D6781F5ED0203010001'),
    'local_wireless' : uhx('307C300D06092A864886F70D0101010500036B003068026100B756E1DCD8CECE78E148107B1BAC115FDB17DE843453CAB7D4E6DF8DD21F5A3D17B4477A8A531D97D57EB558F0D58A4AF5BFADDDA4A0BC1DC22FF87576C7268B942819D4C83F78E1EE92D406662F4E68471E4DE833E5126C32EB63A868345D1D0203010001'), 
}

private_keys = {
    0x3 : int('00775455668FFF3CBA3026C2D0B26B8085895958341157AEB03B6B0495EE57803E2186EB6CB2EB62A71DF18A3C9C6579077670961B3A6102DABE5A194AB58C3250AED597FC78978A326DB1D7B28DCCCB2A3E014EDBD397AD33B8F28CD525054251', 0x10)
}

def get_public_key(key):
    if key not in public_keys:
        return None
    der = public_keys[key]
    N = int(hx(der[0x18:0x79]), 0x10)
    E = int(hx(der[0x7B:0x7E]), 0x10)
    return (N, E, der)

def get_private_key(key):
    if key not in private_keys:
        return None
    D = private_keys[key]
    N, E, der = get_public_key(key)
    return (N, E, D, der)

def sxor(x, y):
    return ''.join([chr(ord(a) ^ ord(b)) for a,b in zip(x,y)])

def aes_ecb_enc(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def aes_ecb_dec(key, block):
    return AES.new(key, AES.MODE_ECB).decrypt(block)

def meme_aes_encrypt(key, buf):
    temp = '\x00' * 0x10
    output = ''
    num_blocks = len(buf)/0x10
    
    # Phase 1: CBC encrypt
    for i in xrange(num_blocks):
        block = buf[i*0x10:(i+1)*0x10]
        temp = aes_ecb_enc(key, sxor(temp, block))
        output += temp

    # Phase 2: Shitty CMAC
    temp = sxor(temp, output[:0x10])
    subkey = [0] * 0x10
    for i in xrange(0, 0x10, 2):
        b1, b2 = up('<BB', temp[i:i+2])
        subkey[i + 0] = (2 * b1 + (b2 >> 7)) & 0xFF
        subkey[i + 1] = (2 * b2) & 0xFF
        if (i + 2 < 0x10):
            subkey[i + 1] += ord(temp[i+2]) >> 7
            subkey[i + 1] &= 0xFF
    if ord(temp[0]) & 0x80:
        subkey[0xF] ^= 0x87
    subkey = ''.join(map(chr, subkey))

    output = sxor(output, subkey * num_blocks)

    # Phase 3: Custom AES mode
    temp = '\x00' * 0x10
    for i in xrange(num_blocks):
        block_ofs = (num_blocks - 1 - i)*0x10
        block = output[block_ofs:block_ofs + 0x10]
        output = output[:block_ofs] + sxor(aes_ecb_enc(key, block), temp) + output[block_ofs+0x10:]
        temp = block

    return output


def meme_aes_decrypt(key, buf):
    temp = '\x00' * 0x10
    output = ''
    num_blocks = len(buf)/0x10

    # Phase 3: Custom AES mode
    for i in xrange(num_blocks):
        block_ofs = (num_blocks - 1 - i)*0x10
        block = buf[block_ofs:block_ofs + 0x10]
        temp = aes_ecb_dec(key, sxor(temp, block))
        output = temp + output

    # Phase 2: Shitty CMAC
    temp = sxor(output[:0x10], output[-0x10:])
    subkey = [0] * 0x10
    for i in xrange(0, 0x10, 2):
        b1, b2 = up('<BB', temp[i:i+2])
        subkey[i + 0] = (2 * b1 + (b2 >> 7)) & 0xFF
        subkey[i + 1] = (2 * b2) & 0xFF
        if (i + 2 < 0x10):
            subkey[i + 1] += ord(temp[i+2]) >> 7
            subkey[i + 1] &= 0xFF
    if ord(temp[0]) & 0x80:
        subkey[0xF] ^= 0x87
    subkey = ''.join(map(chr, subkey))

    output = sxor(output, subkey * num_blocks)

    # Phase 1: AES-CBC
    temp = '\x00' * 0x10
    for i in xrange(num_blocks):
        block_ofs = i*0x10
        block = output[block_ofs:block_ofs + 0x10]
        output = output[:block_ofs] + sxor(aes_ecb_dec(key, block), temp) + output[block_ofs+0x10:]
        temp = block
    return output

def sign_meme_data(data, key=3):
    privk = get_private_key(key)
    if not privk:
        raise ValueError('Private key not known for key %s!' % str(key))
    if len(data) < 0x60:
        raise ValueError('Memesigned data must be atleast 0x60 bytes!')
    N, E, D, der = privk
    aes_key = hashlib.sha1(der + data[:-0x60]).digest()[:0x10]

    output = data[:-0x8] + hashlib.sha1(data[:-0x8]).digest()[:0x8]
    meme_enc = meme_aes_encrypt(key, output[-0x60:])
    meme_enc = chr(ord(meme_enc[0]) & 0x7F) + meme_enc[1:]
    rsa_enc = uhx('%0192X' % pow(int(hx(meme_enc), 0x10), D, N))
    return output[:-0x60] + rsa

def verify_meme_data(data, key = None):
    if key is None or key not in public_keys: # By default, try to decrypt with every key we know about.
        for k in public_keys:
            valid, dec = verify_meme_data(data, k)
            if valid:
                return valid, dec
        return False, None
    N, E, der = get_public_key(key)
    aes_key = hashlib.sha1(der + data[:-0x60]).digest()[:0x10]

    rsa_enc = data[-0x60:]
    rsa_dec = uhx('%0192X' % pow(int(hx(rsa_enc), 0x10), E, N))
    for i in [0, 0x80]:
        meme_enc = chr(ord(rsa_dec[0]) | i) + rsa_dec[1:]
        meme_dec = meme_aes_decrypt(aes_key, meme_enc)
        output = data[:-0x60] + meme_dec
        if hashlib.sha1(output[:-0x8]).digest()[:0x8] == output[-0x8:]:
            return True, output
    return False, None
