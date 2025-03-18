import requests
import sys
import argparse
import threading
import time
from urllib.parse import urljoin
from print_color import print
from itertools import cycle

# Argument parser
parser = argparse.ArgumentParser(description='Requests.')
parser.add_argument('-u', '--url', dest='target_url', help='https://site.com/', required=True)
parser.add_argument('-w', '--wordlist', dest='list', help='Path to your wordlist file', required=True)
parser.add_argument('-r', '--recursive', action='store_true', help='Recursive fuzzing mode', required=False)
parser.add_argument('-fc', '--filter-codes', dest='filter_codes', help='Status codes to show in real time (e.g.: 200,301,403)', required=False)
args = parser.parse_args()

# Validação da URL
if not args.target_url.startswith(('http://', 'https://')):
    print("Erro: A URL deve começar com 'http://' ou 'https://'", color='red')
    sys.exit(1)

# Variáveis globais
target = args.target_url.rstrip('/')  # Remove barra final para evitar erros
wordlist = args.list
recursive_mode = args.recursive  # Ativa modo recursivo
max_depth = 3  # Limite de profundidade para evitar loops infinitos
visited_dirs = set()  # Set para evitar repetição de diretórios
lock = threading.Lock()  # Lock para evitar problemas de concorrência nos prints
found_dirs = []  # Armazena diretórios encontrados
errors = []  # Armazena outros status codes
loading = False  # Controle da barra de loading
active_threads = 0  # Contador de threads ativas
filter_codes = set()  # Lista de status codes a exibir em tempo real

# Configura os status codes que serão mostrados em tempo real
if args.filter_codes:
    try:
        filter_codes = set(map(int, args.filter_codes.split(',')))
    except ValueError:
        print("Erro: O argumento -fc deve conter apenas números separados por vírgula (ex: -fc 200,301,403)", color='red')
        sys.exit(1)

# Função para exibir a barra de progresso e threads ativas
def loading_spinner():
    spinner = cycle(["|", "/", "-", "\\"])
    global loading
    while loading:
        with lock:
            print(f"\r[INFO] Scanning: {target} {next(spinner)} | Threads ativas: {threading.active_count() - 1} ", end="", flush=True)
        time.sleep(0.1)


def fuzzing(base_url, depth=1):    
    global active_threads

    if depth > max_depth:
        return  

    # Evita re-executar a varredura no mesmo diretório
    if base_url in visited_dirs:
        return
    visited_dirs.add(base_url)

    with lock:
        active_threads += 1  
    try:
        with open(wordlist, 'r') as file:
            if depth == 1:
                with lock:
                    print(f"\n\n[INFO] Fuzzing principal em: {base_url}", tag='info', tag_color='blue')

            for directory in file:
                dir = directory.strip()
                url = urljoin(base_url + '/', dir).rstrip('/')  # Usa urljoin e remove barras extras

                headers = {'User-Agent': 'Dirrecon tool/1.0'}
                response = requests.get(url=url, headers=headers)
                code = response.status_code

                with lock:
                    if depth == 1 and code in filter_codes:
                        if code == 403:
                            print(f"{code} -> {url}", tag='forbidden', tag_color='red', color='white')
                        elif code == 200:
                            print(f"{code} -> {url}", tag='success', tag_color='green', color='white')
                        elif code == 404:
                            print(f"{code} -> {url}", tag='not found', tag_color='yellow', color='white')
                        elif code == 502:
                            print(f"{code} -> {url}", tag='BAD GATEWAY', tag_color='orange', color='white')

                    elif depth > 1 and code == 200:  
                        print(f"\n[INFO] Fuzzing em: {base_url} (subdiretório)", tag='info', tag_color='cyan')
                        print(f"{code} -> {url}", tag='success', tag_color='green', color='white')

                    # Armazena os resultados para exibição no final
                    if code == 200:
                        found_dirs.append(url)
                        if recursive_mode:
                            thread = threading.Thread(target=fuzzing, args=(url, depth + 1))
                            thread.start()
                    else:
                        errors.append((code, dir))

    except FileNotFoundError:
        with lock:
            print("\n[ERROR] Wordlist não encontrada!", color='red')
        sys.exit(1)
    except requests.RequestException as e:
        with lock:
            print(f"\n[ERROR] Falha ao acessar {base_url}: {e}", color='red')

    with lock:
        active_threads -= 1  # Diminui contador de threads

def main():
    global loading
    loading = True

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
        
        Usage ---->   Menu : python3 trudir.py -u <URL> -w <WORDLIST_PATH> -fc <200,301,403>
                      Choose the status code that you want to check

        trudir v1.2
        Last update: Mar, 2025
        Contact: true5mail _at_ proton.me
        """, color='cyan')

    # Inicia a barra de loading em uma thread separada
    spinner_thread = threading.Thread(target=loading_spinner, daemon=True)
    spinner_thread.start()

    fuzzing(target)

    # Aguarda todas as threads terminarem antes de exibir os resultados
    while threading.active_count() > 1:
        time.sleep(0.5)

    # Finaliza a barra de loading
    loading = False
    time.sleep(0.2)  # Pequena pausa para limpar a barra no output
    print("\r[INFO] Scan finalizado. Exibindo resultados...\n", flush=True)

    # Exibe os resultados segmentados
    if found_dirs:
        print("\n[✔] Diretórios encontrados:", color='green')
        for d in found_dirs:
            print(f"  - {d}", color='green')

    if errors:
        print("\n[✖] Diretórios não encontrados ou bloqueados:", color='red')
        for code, dir in errors:
            print(f"  {code} -> /{dir}", color='yellow')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        with lock:
            print("\n[INFO] Stopping trudir.", color='red')
        sys.exit(0)