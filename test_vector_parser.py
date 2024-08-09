import argparse
from test_vector_aesgcm_parser import AESGCMParser

SUPPORTED_CRYPTOES = ['aesgcm']

def parse_arguments():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("crypto",
                            help="Crypto algorithm that you want to use",
                            choices=SUPPORTED_CRYPTOES)
    argparser.add_argument("input",
                            help="Input file that will be dumped to output file")
    argparser.add_argument("output",
                            help="Output file that will be dumped from input file")
    return argparser.parse_args()

def main():
    args = parse_arguments()

    if args.crypto.upper() == 'AESGCM':
        parser = AESGCMParser(args.input, args.output)
    parser.parse()

if __name__ == '__main__':
    main()
