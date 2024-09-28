import requests
import sys
from print_color import print
import argparse


# arguments parser 
parser = argparse.ArgumentParser(description='Requests.')
parser.add_argument('-u', '--url', dest='target_url',help='https://site.com/', required=True)
parser.add_argument('-w', '--wordlist', dest='list', help='path to your wordlist file', required=False)
parser.add_argument('-r', '--recursive', help='Recursive fuzzing mode', required=False)
args = parser.parse_args()

if not len(args.target_url) > 1:
    print('''
    python3 trudir.py -h/--help
    
    -u --url The target url (e.g.: https://site.com/)
    -w --wordlist The wordlist file to be used. If none is select trudir will your its own. (e.g.: /usr/share/wordlist/dirb/big.txt)
    -r --recursive Recursive mode while fuzzing for directories or files

    Usage: 

    python3 trudir.py -u https://site.com -w /usr/share/wordlist/dirb/big/txt -r 
    ''')

# arguments and variables 
target = args.target_url
wordlist = args.list
default_wordlist = './lista.txt'

if not wordlist:
    wordlist = default_wordlist

# functions
def main():
    with open(wordlist, 'r') as line:
        print(f'Starting scanning: {target}')
        for directory in line:
            dir = directory.strip()

            url = f"{target}/{dir}"

            headers = {'User-Agent': 'Dirrecon tool/1.0'}
            response = requests.get(url=url,headers=headers)
            code = response.status_code
            if (code == 200):
                print(f"{code} ----- Directory found ----------> {url}", tag='success', tag_color='green', color='white', background='black')
            elif (code == 403):
                print(f"{code} ----- Access Forbidden ---------> /{dir}", tag='denied', tag_color='red', color='white')
            else:
                print(f" ---------- Status Code {code} --------------> /{dir}", tag='error', tag_color='yellow', color='white')

if __name__ == "__main__":
    print(
        """ 
          __________  __  ______________   __________  ____  __   _____
        /_  __/ __ \/ / / / ____/ ____/  /_  __/ __ \/ __ \/ /  / ___/
        / / / /_/ / / / / __/ /___ \     / / / / / / / / / /   \__ \ 
        / / / _, _/ /_/ / /_______/ /    / / / /_/ / /_/ / /______/ / 
        /_/ /_/ |_|\____/_____/_____/    /_/  \____/\____/_____/____/  
            \n                                                   
        """, color='cyan', format='blink'
    )
    print(
        """
        ===================================================
        =                                                   =
        =                                                   =
        =            :.        TRUDIR        .:             =
        =                                                   =
        =                                                   =
        =                                                   =
        =       by: TRUE5                                   =
        =                                                   =
        ====================================================

        Usage ---->   Menu : python3 trudir.py -u <URL> -w <WORDLIST_PATH>


        trudir v1.2
        Last update: Sep, 28, 2024
        Contact: true5mail _at_ proton.me
        """, color='cyan')
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping trudir.", color='red')
        sys.exit(0)
