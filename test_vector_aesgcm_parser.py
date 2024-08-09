import json
from sys import stdout
from typing import Tuple

from test_vector_parser_interface import Parser
from test_vector_packet import Packet

class AESGCMParser(Parser):
    # This parser works with following assumptions to parse .rsp file
    # 1. Single .rsp file contains either encryption or decryption test cases only
    # 2. Metadata format : "[Metadata_name = Metadata_value_int]\n"
    # 3. Each single test case starts with 'Count' line

    RSP_CONFIG_ORDER  = ('Keylen', 'IVlen', 'PTlen', 'AADlen', 'Taglen')
    RSP_TEST_CASE_FIELD_ORDER = ('Key', 'IV', 'CT', 'AAD', 'Tag', 'PT')

    JSON_CONFIG_FIELD_ORDER    = ('keyLen', 'ivLen', 'payloadLen', 'aadLen', 'tagLen')
    JSON_TEST_CASE_FIELD_ORDER = ('key', 'iv', 'ct', 'aad', 'tag', 'pt')
    JSON_FIELD_TO_CONFIG       = {'key': 'keyLen', 'iv': 'ivLen', 'ct': 'payloadLen',
                                  'pt': 'payloadLen', 'aad': 'aadLen', 'tag': 'tagLen'}

    def __init__(self, input_filename, outfile_filename):
        if input_filename.endswith('.rsp') and outfile_filename.endswith('.bin'):
            self.infile  = open(input_filename, "r")
            self.outfile = open(outfile_filename, "wb+")
            self.mode    = 'rsp_to_bin'

        elif input_filename.endswith('.json') and outfile_filename.endswith('.bin'):
            self.infile  = open(input_filename, "r")
            self.outfile = open(outfile_filename, "wb+")
            self.mode    = 'json_to_bin'

        elif input_filename.endswith('.bin') and outfile_filename.endswith('.json'):
            self.infile  = open(input_filename, "rb")
            self.outfile = open(outfile_filename, "w")
            self.mode    = 'bin_to_json'

        else:
            print("[ERROR] Wrong input/output argument")
            raise ValueError

        self.packets: list = list()
        self.total_packet_size: int = 0

    def parse(self):
        if self.mode == 'rsp_to_bin':
            self.rsp_to_bin_parse()
        elif self.mode == 'json_to_bin':
            self.json_to_bin_parse()
        elif self.mode == 'bin_to_json':
            self.bin_to_json_parse()
        else:
            print("[ERROR] Wrong mode")
            raise ValueError

    def rsp_skip_until_brackets(self) -> str:
        crypto_packet = Packet('CRYPTO')
        crypto_packet.fill_crypto_header('AESGCM', False, False)

        while True:
            line = self.infile.readline()

            if 'Encrypt' in line:
                self.mode = 'Encrypt'
            elif 'Decrypt' in line:
                self.mode = 'Decrypt'

            # Stop skipping
            if line.startswith('['):
                self.packets.append(crypto_packet)
                self.total_packet_size += crypto_packet.get_packet_size() + 4
                return line

    def rsp_parse_config(self, line: str) -> Tuple[int, str]:
        len_data_dict = dict()
        config_packet = Packet('CONFIG')
        config_packet.fill_config_header(len(self.RSP_CONFIG_ORDER), self.mode)

        while line.startswith('['):
            config_name = line.split(' = ')[0].lstrip('[')
            length_data = line.split(' = ')[1].rstrip(']\n')

            len_data_dict[config_name] = int(length_data)
            line = self.infile.readline()

        for config_name in self.RSP_CONFIG_ORDER:
            len_data = len_data_dict[config_name]
            stdout.write(str(len_data) + ' ')
        stdout.write('\n')

        for config_name in self.RSP_CONFIG_ORDER:
            len_data = len_data_dict[config_name]
            config_packet.payload_append_data(
                len_data.to_bytes(4, byteorder='little')
            )

        self.packets.append(config_packet)
        self.total_packet_size += config_packet.get_packet_size()

        ptlen = (len_data_dict['PTlen'] + 7) // 8
        while not line.startswith('Count'):
            line = self.infile.readline()

        return (ptlen, line)

    def rsp_parse_test_case(self, ptlen: int, line: str) -> str:
        # Note: assuming that 'Count' line was already read away
        fields_dict = dict()
        failed_tc = False
        test_case_packet = Packet('TEST_CASE')

        while line != '\n' and line != '':
            if line == 'FAIL\n':
                fields_dict['PT'] = 'FAIL'
                line = self.infile.readline()
                continue

            field_name = line.split('=')[0].rstrip(' ')
            field_value = line.split('=')[1].lstrip(' ').rstrip('\n')
            fields_dict[field_name] = field_value
            line = self.infile.readline()

        for field_name in self.RSP_TEST_CASE_FIELD_ORDER:
            field_value = fields_dict[field_name]
            # If 'FAIL' comes in instead of PT data, dump PT as all '0's
            if field_value == 'FAIL':
                failed_tc = True
                test_case_packet.payload_append_data(bytes(ptlen))
                continue

            test_case_packet.payload_append_data(bytes.fromhex(field_value))

        if failed_tc:
            test_case_packet.fill_test_case_header('FAIL')
        else:
            test_case_packet.fill_test_case_header('PASS')

        self.packets.append(test_case_packet)
        self.total_packet_size += test_case_packet.get_packet_size()

        return line

    def rsp_to_bin_parse(self) -> None:
        iter = 1
        reached_eof = False

        self.direction = None
        line = self.rsp_skip_until_brackets()

        while not reached_eof:
            stdout.write(f"Option {iter} configs: ")
            iter += 1

            ptlen, line = self.rsp_parse_config(line)

            while True:
                line = self.rsp_parse_test_case(ptlen, line)

                while line == '\n':
                    line = self.infile.readline()

                if line.startswith('Count'):
                    continue
                elif line.startswith('['):
                    break
                elif line == '':
                    reached_eof = True
                    break

        self.dump_packets_to_binary()

    def json_metadata_dump(self, metadata):
        temp_json = open("temp.json", "w")
        json.dump(metadata, temp_json, indent='\t')
        temp_json.close()

    def json_metadata_load(self):
        temp_json = open("temp.json", "r")
        metadata = json.load(temp_json)
        temp_json.close()
        return metadata

    def json_to_bin_parse(self):
        json_input = json.load(self.infile)
        self.json_metadata_dump(json_input[0])
        vector_set = json_input[1]

        crypto_packet = Packet('CRYPTO')
        crypto_packet.fill_crypto_header('AESGCM', True, False)
        crypto_packet.payload_append_data(
            int(vector_set['vsId']).to_bytes(4, byteorder='little')
        )
        # NOTE: 4 bytes of additional payload(total binary size)
        #       is reserved for crypto packet
        self.total_packet_size += crypto_packet.get_packet_size() + 4
        self.packets.append(crypto_packet)

        for test_group in vector_set["testGroups"]:
            config_packet = Packet('CONFIG')
            config_packet.fill_config_header(len(self.JSON_CONFIG_FIELD_ORDER), test_group["direction"])

            for config in self.JSON_CONFIG_FIELD_ORDER:
                config_packet.payload_append_data(
                    int(test_group[config]).to_bytes(4, byteorder='little')
                )

            config_packet.payload_append_data(
                int(test_group["tgId"]).to_bytes(4, byteorder='little')
            )
            self.total_packet_size += config_packet.get_packet_size()
            self.packets.append(config_packet)

            for test_case in test_group["tests"]:
                test_case_packet = Packet('TEST_CASE')
                test_case_packet.fill_test_case_header('PASS')

                for field in self.JSON_TEST_CASE_FIELD_ORDER:
                    if field not in test_case:
                        data = bytes(test_group[self.JSON_FIELD_TO_CONFIG[field]] // 8)
                    else:
                        data = bytes.fromhex(test_case[field])
                    test_case_packet.payload_append_data(data)

                test_case_packet.payload_append_data(
                    int(test_case["tcId"]).to_bytes(4, byteorder='little')
                )
                self.total_packet_size += test_case_packet.get_packet_size()
                self.packets.append(test_case_packet)

        self.dump_packets_to_binary()

    def dump_packets_to_binary(self):
        assert self.packets[0].packet_type == 'CRYPTO'
        prev_payload = self.packets[0].get_payload()

        self.packets[0].payload_set_data(
            self.total_packet_size.to_bytes(4, byteorder='little')
        )
        self.packets[0].payload_append_data(prev_payload)

        for packet in self.packets:
            self.outfile.write(packet.get_packet())

    def get_endian_converted_uint32(self) -> int:
        uint32_little = self.infile.read(4)
        return int.from_bytes(uint32_little, byteorder='little')

    def bin_to_json_parse(self):
        json_output = dict()
        json_output['testGroups'] = []
        curr_test_group = None
        curr_test_case  = None
        text_len        = None
        tag_len         = None
        direction       = None

        while True:
            uint32_little = self.infile.read(4)
            # Reached EOF
            if not uint32_little:
                break

            header = int.from_bytes(uint32_little, byteorder='little')
            packet_type = header & Packet.PACKET_TYPE_MASK

            if packet_type == Packet.PACKET_TYPE_CRYPTO:
                self.infile.read(4)
                json_output['vsId'] = self.get_endian_converted_uint32()

            elif packet_type == Packet.PACKET_TYPE_CONFIG:
                configs_num = (header & Packet.CONFIGS_NUM_MASK) >> Packet.CONFIGS_NUM_SHIFT
                direction = header & Packet.CONFIG_DIR_MASK

                curr_test_group = dict()
                tgId = self.get_endian_converted_uint32()
                text_len = self.get_endian_converted_uint32()
                if configs_num == 2:
                    tag_len = self.get_endian_converted_uint32()
                else:
                    tag_len = 0

                curr_test_group['tgId'] = tgId
                curr_test_group['tests'] = list()
                json_output['testGroups'].append(curr_test_group)

            elif packet_type == Packet.PACKET_TYPE_TEST_CASE:
                test_case_result = header & Packet.TEST_CASE_RESULT_MASK

                curr_test_case = dict()
                tcId = self.get_endian_converted_uint32()
                text = self.infile.read(text_len).hex()
                if test_case_result == Packet.TASE_CASE_RESULT_PASS:
                    testPassed = True
                elif test_case_result == Packet.TEST_CASE_RESULT_FAIL:
                    testPassed = False
                else:
                    print("[ERROR] Invalid test case result")
                    raise ValueError

                curr_test_case['tcId'] = tcId
                if direction == Packet.CONFIG_DIR_ENCRYPT:
                    tag = self.infile.read(tag_len).hex()
                    curr_test_case['ct'] = text
                    curr_test_case['tag'] = tag
                elif direction == Packet.CONFIG_DIR_DECRYPT:
                    if testPassed:
                        curr_test_case['pt'] = text
                    else:
                        curr_test_case['testPassed'] = 'false'
                else:
                    print("[ERROR] Invalid direction")
                    raise ValueError

                curr_test_group['tests'].append(curr_test_case)

            else:
                print("[ERROR] Invalid packet type:")
                print(header.to_bytes(4, byteorder='little').hex())
                raise ValueError

        metadata = self.json_metadata_load()
        json.dump([metadata, json_output], self.outfile, indent='\t')
