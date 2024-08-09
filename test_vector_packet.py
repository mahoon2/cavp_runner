class Packet():

    # Packet type (2 bits)
    PACKET_TYPE_MASK      = 0b11000000_00000000_00000000_00000000
    PACKET_TYPE_UNMASK    = 0b00111111_11111111_11111111_11111111
    PACKET_TYPE_CRYPTO    = 0b00 << 30
    PACKET_TYPE_CONFIG    = 0b01 << 30
    PACKET_TYPE_TEST_CASE = 0b10 << 30

    # Payload size (14 bits, up to 32,767 bytes)
    PAYLOAD_MASK          = 0b00111111_11111111_00000000_00000000
    PAYLOAD_UNMASK        = 0b11000000_00000000_11111111_11111111
    PAYLOAD_SHIFT         = 16

    ####### CRYPTO packet #######
    ## Algorithm (10 bits)
    CRYPTO_ALGORITHM_MASK      = 0b00000000_00000000_11111111_11000000
    CRYPTO_ALGORITHM_UNMASK    = 0b11111111_11111111_00000000_00111111
    CRYPTO_ALGORITHM_AESGCM    = 0b00000000_01 << 6

    ## ACVTS flag (1 bit)
    CRYPTO_ACVTS_MASK          = 0b00000000_00000000_00000000_00100000
    CRYPTO_ACVTS_UNMASK        = 0b11111111_11111111_11111111_11011111
    CRYPTO_ACVTS_FLAG          = 0b1 << 5

    ## Response flag (1 bit)
    CRYPTO_RESPONSE_MASK       = 0b00000000_00000000_00000000_00010000
    CRYPTO_RESPONSE_UNMASK     = 0b11111111_11111111_11111111_11101111
    CRYPTO_RESPONSE_FLAG       = 0b1 << 4

    ####### CONFIG packet #######
    ## Number of configs (4 bits)
    CONFIGS_NUM_MASK           = 0b00000000_00000000_11110000_00000000
    CONFIGS_NUM_UNMASK         = 0b11111111_11111111_00001111_11111111
    CONFIGS_NUM_SHIFT          = 12

    ## Direction (2 bits)
    CONFIG_DIR_MASK            = 0b00000000_00000000_00001100_00000000
    CONFIG_DIR_UNMASK          = 0b11111111_11111111_11110011_11111111
    CONFIG_DIR_ENCRYPT         = 0b00 << 10
    CONFIG_DIR_DECRYPT         = 0b01 << 10

    ###### TEST_CASE packet ######
    ## TC result (1 bit)
    TEST_CASE_RESULT_MASK      = 0b00000000_00000000_10000000_00000000
    TEST_CASE_RESULT_UNMASK    = 0b11111111_11111111_01111111_11111111
    TEST_CASE_RESULT_FAIL      = 0b0 << 15
    TASE_CASE_RESULT_PASS      = 0b1 << 15

    def __init__(self, packet_type: str):
        self.packet_type  = packet_type.upper()
        self.header       = None
        self.payload      = bytes()

        if packet_type == 'CRYPTO':
            self.header = self.PACKET_TYPE_CRYPTO
        elif packet_type == 'CONFIG':
            self.header = self.PACKET_TYPE_CONFIG
        elif packet_type == 'TEST_CASE':
            self.header = self.PACKET_TYPE_TEST_CASE
        else:
            raise ValueError

    def __fill_payload_size(self, payload_size: int):
        payload_size >>= 2
        if payload_size >= 2**15:
            raise OverflowError
        self.header &= self.PAYLOAD_UNMASK
        self.header |= (payload_size << self.PAYLOAD_SHIFT)

    def fill_crypto_header(self,
                           algorithm: str,
                           acvts: bool = False,
                           rsp: bool = False):
        if self.packet_type != 'CRYPTO':
            raise TypeError

        self.header &= self.CRYPTO_ALGORITHM_UNMASK
        if algorithm.upper() == 'AESGCM':
            self.header |= self.CRYPTO_ALGORITHM_AESGCM
        else:
            raise ValueError

        self.header &= self.CRYPTO_ACVTS_UNMASK
        if acvts:
            self.header |= self.CRYPTO_ACVTS_FLAG

        self.header &= self.CRYPTO_RESPONSE_UNMASK
        if rsp:
            self.header |= self.CRYPTO_RESPONSE_FLAG

    def fill_config_header(self, num_configs: int, direction: str):
        if self.packet_type != 'CONFIG':
            raise TypeError
        if num_configs >= 2**5:
            raise OverflowError

        self.header &= self.CONFIGS_NUM_UNMASK
        self.header |= (num_configs << self.CONFIGS_NUM_SHIFT)

        self.header &= self.CONFIG_DIR_UNMASK
        if direction.upper() == 'ENCRYPT':
            self.header |= self.CONFIG_DIR_ENCRYPT
        elif direction.upper() == 'DECRYPT':
            self.header |= self.CONFIG_DIR_DECRYPT
        else:
            raise ValueError

    def fill_test_case_header(self, test_case_result: str):
        if self.packet_type != 'TEST_CASE':
            raise TypeError

        self.header &= self.TEST_CASE_RESULT_UNMASK
        if test_case_result.upper() == 'PASS':
            self.header |= self.TASE_CASE_RESULT_PASS
        elif test_case_result.upper() == 'FAIL':
            self.header |= self.TEST_CASE_RESULT_FAIL
        else:
            raise ValueError

    def payload_append_data(self, data: bytes):
        self.payload += data
        align = len(data) % 4
        if align:
            self.payload += bytes(4 - align)

    def payload_set_data(self, data: bytes):
        self.payload = data
        align = len(data) % 4
        if align:
            self.payload += bytes(4 - align)

    def get_payload(self) -> bytes:
        return self.payload

    def get_packet_size(self) -> int:
        return len(self.payload) + 4

    def get_packet(self) -> bytes:
        self.__fill_payload_size(len(self.payload))
        print(f"header: {hex(self.header)}")
        return self.header.to_bytes(4, byteorder='little') + self.payload
