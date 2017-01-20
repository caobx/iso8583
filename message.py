# coding:  utf-8
import json
from collections import OrderedDict
import pyDes
import binascii
import datetime
import codecs
from config import (root, fields, tran_code)

class Message:

    def __init__(self):
        self.__bits = {};
        self.extend_map = True
        self.__bit_map = None
        self.__trace_num = None

    def message_header(self):
        d = OrderedDict(sorted(self.__bits.items(), key=lambda t: t[0]))
        message_header = ''.join([d[x] for x in d if x < -1])
        if message_header is '':
            TPDU = '00000'
            net_flag = '01'
            self.__trace_num = self.__trace_num if self.__trace_num is not None else self.trace_number()
            err_code = '0000'
            return TPDU + net_flag + self.__trace_num + err_code
        else:
            return message_header

    def trace_number(self):
        with open('data.json') as data_file:
            data = json.load(data_file)
            trace_number = data['trace_number']
            new_trace_number = 0 if trace_number == '99999999' else int(trace_number) + 1
            data['trace_number'] = '%08d' % new_trace_number
        with open('data.json', 'w') as data_file:
            json.dump(data, data_file)
        return trace_number

    def trace_num(self):
        return self.__trace_num if self.__trace_num is not None else self.trace_number()

    def date(self):
        return datetime.datetime.now().strftime('%Y%m%d')

    def time(self):
        return datetime.datetime.now().strftime('%H%M%S')

    def set_bit(self, bit, value):
        if type(value) is list:
            value = ''.join(value)
        elif type(value) is dict:
            bits = OrderedDict(sorted(value.items(), key=lambda t: t[0]))
            value = ''.join(bits.values())

        field = root.get(bit)
        if field is None:
            raise Exception('invalid bit value')
        if field['class'] is 'V':
            self.__bits[bit] = self.pack_fixed_length_bit(bit, value, field)
            print(bit, ': ', self.__bits[bit], 'value = ', value)
        else:
            self.__bits[bit] = self.pack_varient_length_bit( bit, value, field)

    # 固定长度域数字类型前补0, 非数字后补空格
    def pack_fixed_length_bit(self, bit, value, field):
        if field['type'] is 'N' or field['type'] is 'AN':
            if field['code'] is 'ASCII':
                if len(value) < field['len']:
                    return (field['len'] - len(value)) * '0' + value
                else:
                    return value[:field['len']]
            elif field['code'] is 'BCD':
                if len(value) % 2 is 1:
                    value = '0' + value
                if len(value) < field['len']:
                    value = (field['len'] - len(value)) * '0' + value

                    return self.string_to_bcd(value)
                else:
                    value = value[:field['len']]
                    print('bcd = ', self.string_to_bcd(value))
                    return self.string_to_bcd(value)
            else:
                raise Exception('Invaid Code')
        else:
            if len(value) < field['len']:
                return value + (field['len'] - len(value)) * ' '
            else:
                return value[:field['len']]


    def pack_varient_length_bit(self, bit, value, field):
        len_code = field.get('len_code')
        if len_code is None:
            len_code = field['code']
        if len_code is 'ASCII' or len_code is 'BYTES':
            len_bytes = len(field['class'][1:])
            len_value = format(len(value), '0' + str(len_bytes))
            return len_value + value
        elif len_code is 'BCD':
            if len(value) % 2 is 1:
                value += '0'
            len_bytes = len(field['class'][1:])
            if len_bytes % 2 is 1:
                len_bytes += 1
            len_value = format(len(value), '0' + str(len_bytes))
            return self.string_to_bcd(len_value) + value
        else:
            raise Exception('Invaid Code', len_code)


    def bit(self, bit):
        return self.__bits[bit]

    def string_to_bcd(self, value):
        return codecs.decode(bytes(value, 'ascii'), 'hex').decode('ascii')

    def bcd_to_string(self, data):
        return codecs.encode(bytes(value, 'ascii'), 'hex').decode('ascii')

    def bit_map(self):
        if self.__bit_map is not None:
            return self.__bit_map
        self.__bit_map = ''
        bits = OrderedDict(sorted(self.__bits.items(), key=lambda t: t[0]))
        bits = [x for x in bits.keys() if x > 0]
        bit_list = list('0' * (128 if self.extend_map else 64))
        if (self.extend_map):
            bit_list[0] = '1'
        for x in bits:
            bit_list[x - 1] = '1'
        i = 0
        while (i < len(bit_list)):
            # print('eafe', int(''.join(bit_list[i:i+4]), 2))
            h = '0123456789ABCDEF'
            self.__bit_map += h[int(''.join(bit_list[i:i+4]), 2)]
            i += 4
        return self.__bit_map

    def bits(self):
        # print(__bits)
        return self.__bits

    def MAC(self):
        mab = self.format_data()
        key = bytes.fromhex(self.MACKey())
        k = pyDes.triple_des(key, pyDes.CBC, b'\0\0\0\0\0\0\0\0', 0)
        res = k.encrypt(mab)
        return binascii.hexlify(res[-8:]).upper().decode()

    def format_data(self):
        join_mac_bits = [-1, 2, 3, 4, 11, 12, 13, 39, 53, 68, 102, 103]
        bits = sorted([x for x in self.__bits if x in join_mac_bits])
        vals = [self.__bits[x].strip() for x in bits]
        res = []
        for s in vals:
            ele = ''
            s = ' '.join(s.split())
            for c in s:
                if c.isalnum or c in ' ,.':
                    ele += c
            res.append(ele)
        res = ' '.join(res)
        res += (8 - len(res) % 8) * '\0'
        return res

    def MACKey(self):
        with open('data.json') as f:
            data = json.load(f)
            key = data['MACKey']
        return key

    def finish(self):
        header = self.message_header()
        message_type = self.__bits[-1]

        if self.__bits.get(11) is None:
            self.__bits[11] = self.__trace_num
        if self.__bits.get(12) is None:
            self.__bits[12] = self.time()
        if self.__bits.get(13) is None:
            self.__bits[13] = self.date()

        bit_map = self.bit_map()

        d = OrderedDict(sorted(self.__bits.items(), key=lambda t: t[0]))
        message_body = ''.join([d[x] for x in d if x > -1])
        m = self.to_hex(header + message_type) + bit_map + self.to_hex(message_body) + self.MAC()
        return format(len(m)//2, '04X') + m

    def to_hex(self, data):
        return binascii.hexlify(bytes(data, 'ascii')).decode('ascii')

    def unpack(self, data):
        res = []
        bits = sorted(root.keys())
        data = self.check_len(data, bits, res)
        data = self.unpack_header(data, bits, res)

        data, bit_map = self.search_message(data, bits, res)


        body_bits = []
        for i, v in enumerate(bit_map):
            if v is '1' and i is not 0:
                body_bits.append(i+1)

        data = self.unpack_body(data, body_bits, res)
        if data is not '':
            print('报文长度不对，还剩余', data)


        tran = self.find_tran(res)
        if tran is None:
            print('找不到交易类型')
        print('交易类型: ', tran)
        print(res)
        return (tran, res)

    def check_len(self, data, bits, res):
        bit = bits[0]
        len_bytes = root[bit]['len']
        len_value = int(data[:len_bytes * 2], 16)
        if len_value != len(data[len_bytes * 2:]) / 2:
            print('warning', '报文长度不正确')
        d = {}
        d['field'] = bit
        d['name'] = root[bit]['name']
        d['value'] = len_value
        d['bytes'] = data[:len_bytes * 2]
        res.append(d)
        return data[len_bytes * 2:]

    def unpack_header(self, data, bits, res):
        head = [x for x in bits if x < -1][1:]
        for bit in head:
            data = self.__unpack(data, root[bit], bit, res)
        return data

    def unpack_body(self, data, bits, res):
        for b in bits:
            data = self.__unpack(data, root[b], b, res)
        return data


    def search_message(self, data, bits, res):
        data = self.__unpack(data, root[-1], -1, res)
        (data, bit_map) = self.unpack_bitmap(data, res)
        return data, bit_map

    def find_tran(self, res):
        for v in res:
            if v['field'] is -1:
                message_type = v['value']
            if v['field'] is 3:
                message_code = v['value']
                break
        if len(message_type) is not 4 and message_code is not 6:
            print('找不到交易类型')
            return None

        for v in tran_code:
            if message_type == v[1]:
                if message_code == v[3]:
                    return v[0] + '_请求报文'
            if message_type == v[2]:
                if message_code == v[3]:
                    return v[0] + '_响应报文'
        return None

    def unpack_bitmap(self, data, res):
        bit_map_bytes = data[:16]
        data = data[16:]
        bit_map = ''.join([format(int(x, 16), '04b') for x in bit_map_bytes])
        if bit_map[0] is '1':
            bit_map_bytes += data[:16]
            data = data[16:]
            bit_map += ''.join([format(int(x, 16), '04b') for x in bit_map_bytes[16:]])
        res.append({'name': '位图', 'field': 0, 'bytes': bit_map_bytes, 'value': bit_map})
        return (data, bit_map)

    def __unpack(self, data, field, bit, res):
        length = field['len']
        code = field['code']
        d = {'name': field['name'], 'field': bit}
        if field['class'] is 'V':
            (data, (chunk, value)) = self.unpack_fixed_length(data, length, code)
        else:
            len_code = field.get('len_code')
            if len_code is None:
                len_code = code
            (data, (chunk, value)) = self.unpack_varient_length(data, field['class'][:-1], code, len_code)
        d['bytes'] = chunk
        d['value'] = value
        res.append(d)
        return data

    def unpack_fixed_length(self, data, length, code):
        if code is 'BCD':
            if length % 2 is 1:
                length += 1
            chunk = data[:length]
            value = bcd_to_string(data[:length])
            value = binascii.unhexlify(value).decode()
            return (data[length*2:], (chunk, value))
        elif code is 'ASCII':
            chunk = data[:length*2]
            value = binascii.unhexlify(data[:length*2]).decode()
            return (data[length*2:], (chunk, value))
        else:
            chunk = data[:length*2]
            value = data[:length*2]
            return (data[length*2:], (chunk, value))

    def unpack_varient_length(self, data, len_type, code, len_code):
        if len_code is 'BCD':
            length = len(len_type)
            if length % 2 is 1:
                length += 1
        else:
            length = len(len_type)
        (data, (len_chunk, len_value)) = self.unpack_fixed_length(data, length, len_code)
        (data, (body_chunk, body_value)) = self.unpack_fixed_length(data, int(len_value), len_code)
        chunk = len_chunk + body_chunk
        value = len_value + body_value
        return (data, (chunk, value))



if __name__ == '__main__':

    data = '016B3030303030303130303030303732363030303030383130A23A0000028000000000000800000102313930323030313030303030303732363039323030313230313730313036323031343131313430303839393132303835303030313538303033303536303031323030313930313233343536373839303132333435363738303030303030303030303139313130303030303030303030303030303030343530303232303030383632323135313830303030303030303030303139313131313130303130303030303030303030343530303332303030383632323138383739303030303030303030303139313131313131303130303030303030303031303938333030303330393030303030303939303939393939393939393931393030303030393030323030333038303037323030373430303132303230353030303030323330313132313431333130303131433133303030313030313233343031313233343031313233343939393939'
    t = Message()
    t.unpack(data)
