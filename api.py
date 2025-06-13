import logging # Módulo para registrar eventos e informações sobre a execução do programa.
from flask import Flask, request, jsonify # Flask é um microframework web; request para lidar com requisições HTTP; jsonify para retornar respostas JSON.
from flask_cors import CORS # Extensão do Flask para Cross-Origin Resource Sharing (CORS), permitindo requisições de domínios diferentes.
import nmap # Biblioteca Python para interagir com o Nmap, uma ferramenta de segurança de rede.
import re # Módulo para operações com Expressões Regulares (regex), usado para buscar padrões em strings.
import shutil # Módulo para operações de alto nível em arquivos e coleções de arquivos, usado aqui para verificar se o Nmap está instalado.
import requests # Biblioteca para fazer requisições HTTP, usada para consultar a API do NVD.
import time # Módulo para funções relacionadas a tempo, usado para adicionar atrasos.
import json # Módulo para trabalhar com dados JSON (codificar e decodificar).
import os # Módulo para interagir com o sistema operacional, como caminhos de arquivo.

# Configuração de logging
# Configura o sistema de log básico para exibir mensagens informativas (INFO) ou superiores.
# O formato inclui timestamp, nível da mensagem e a mensagem em si.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Inicialização do aplicativo Flask
app = Flask(__name__)
# Habilita o CORS para todas as rotas da aplicação, permitindo que o frontend em um domínio diferente
# faça requisições para esta API.
CORS(app)

# --- Variáveis de Configuração Global ---

# Caminho para o arquivo de cache de CVEs. Este arquivo armazenará os detalhes das CVEs
# para evitar múltiplas requisições à API do NVD para a mesma CVE.
CVE_CACHE_FILE = 'cve_cache.json'
# Cache em memória para armazenar os detalhes das CVEs do NVD.
# É um dicionário onde a chave é o ID da CVE (ex: 'CVE-2023-1234') e o valor são seus detalhes.
cve_details_cache = {}

# Tempo de espera inicial entre as requisições à API do NVD (em segundos).
# Essencial para evitar exceder os limites de taxa (rate limits) da API.
NVD_API_DELAY = 5.0 # Atraso de 5 segundos (inicial) para ser BEM MAIS conservador
# Número máximo de tentativas de consultar a API do NVD para uma única CVE em caso de falha.
MAX_NVD_RETRIES = 10 # AUMENTADO para 10 tentativas de consulta ao NVD para uma única CVE

# NOTA: MAX_NVD_DETAILS_FETCHED_PER_SCAN foi REMOVIDO.
# O objetivo agora é tentar buscar os detalhes para TODAS as CVEs, com a lógica de retentativa
# e cache gerenciada por `get_cve_severity_from_nvd`.

# --- Funções de Utilitário ---

def load_cve_cache():
    """
    Carrega o cache de CVEs de um arquivo JSON.
    Se o arquivo existe, ele tenta lê-lo e decodificar o JSON.
    Em caso de erro (arquivo não encontrado ou JSON inválido), o cache em memória é inicializado vazio.
    """
    global cve_details_cache # Declara que estamos modificando a variável global `cve_details_cache`.
    if os.path.exists(CVE_CACHE_FILE): # Verifica se o arquivo de cache existe.
        try:
            with open(CVE_CACHE_FILE, 'r') as f: # Abre o arquivo em modo de leitura ('r').
                cve_details_cache = json.load(f) # Carrega o conteúdo JSON para o dicionário.
            logging.info(f"Cache de CVEs carregado de {CVE_CACHE_FILE}. Total de {len(cve_details_cache)} CVEs em cache.")
        except json.JSONDecodeError as e: # Captura erro se o JSON no arquivo for inválido.
            logging.error(f"Erro ao decodificar JSON do arquivo de cache {CVE_CACHE_FILE}: {e}. O cache será iniciado vazio.")
            cve_details_cache = {} # Reseta o cache para vazio em caso de erro.
        except Exception as e: # Captura qualquer outro erro inesperado durante o carregamento.
            logging.error(f"Erro ao carregar o cache de CVEs de {CVE_CACHE_FILE}: {e}. O cache será iniciado vazio.")
            cve_details_cache = {} # Reseta o cache para vazio.
    else:
        logging.info(f"Arquivo de cache {CVE_CACHE_FILE} não encontrado. Iniciando cache vazio.")
        cve_details_cache = {} # Inicializa o cache vazio se o arquivo não existe.

def save_cve_cache():
    """
    Salva o cache de CVEs atual (em memória) em um arquivo JSON.
    Isso garante que os dados de CVEs consultados persistam entre as execuções do programa.
    """
    try:
        with open(CVE_CACHE_FILE, 'w') as f: # Abre o arquivo em modo de escrita ('w'). Se o arquivo não existe, ele é criado; se existe, é sobrescrito.
            json.dump(cve_details_cache, f, indent=4) # Escreve o dicionário `cve_details_cache` como JSON no arquivo.
                                                   # `indent=4` formata o JSON com indentação para melhor legibilidade.
        logging.info(f"Cache de CVEs salvo em {CVE_CACHE_FILE}. Total de {len(cve_details_cache)} CVEs em cache.")
    except Exception as e: # Captura qualquer erro que possa ocorrer durante a escrita do arquivo.
        logging.error(f"Erro ao salvar o cache de CVEs em {CVE_CACHE_FILE}: {e}.")

def is_nmap_installed():
    """
    Verifica se o executável do Nmap está disponível no PATH do sistema.
    Usa `shutil.which()` que retorna o caminho completo do executável se encontrado, ou None caso contrário.
    """
    return shutil.which("nmap") is not None # Retorna True se 'nmap' for encontrado no PATH, False caso contrário.

def extract_cves(vulners_output):
    """
    Extrai Common Vulnerabilities and Exposures (CVEs) de uma string que é a saída
    do script 'vulners' do Nmap.
    Usa uma expressão regular para encontrar padrões de CVEs (ex: CVE-YYYY-NNNN).
    """
    # Compila a expressão regular para encontrar padrões de CVEs.
    # r'(CVE-\d{4}-\d{4,7})' busca por "CVE-", seguido por 4 dígitos, um hífen, e 4 a 7 dígitos.
    # re.IGNORECASE faz a busca ser insensível a maiúsculas/minúsculas.
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
    # Encontra todas as ocorrências que correspondem ao padrão na string de entrada.
    return cve_pattern.findall(vulners_output)

def get_cve_severity_from_nvd(cve_id):
    """
    Consulta a API do National Vulnerability Database (NVD) para obter detalhes de uma CVE específica,
    incluindo severidade, pontuação CVSS e um resumo.
    Implementa um mecanismo de cache, retentativas com atraso exponencial e tratamento de erros.
    Retorna uma tupla: (dicionário de detalhes_da_cve, True/False se foi buscado_do_nvd_agora).
    """
    # 1. Verifica o cache em memória
    if cve_id in cve_details_cache:
        logging.info(f"CVE {cve_id} encontrada no cache.")
        return cve_details_cache[cve_id], False # Retorna do cache, indicando que não foi buscado agora.

    # 2. Constrói a URL da API do NVD
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    # 3. Define detalhes padrão para a CVE caso a busca no NVD falhe completamente.
    # MODIFICADO: Default para 'medium' em vez de 'unknown'.
    # Esta será a severidade se TODAS as tentativas falharem.
    default_cve_details = {
        "severity": "medium", # Severidade padrão.
        "cvss_score": None, # Pontuação CVSS padrão.
        "summary": "Detalhes não puderam ser obtidos do NVD ou consulta ignorada após múltiplas tentativas.",
        "references": [] # Referências padrão.
    }

    retries = 0 # Contador de tentativas.
    # 4. Loop de retentativas para consultar a API do NVD
    while retries < MAX_NVD_RETRIES: # Loop continua enquanto `retries` for menor que `MAX_NVD_RETRIES`.
        try:
            # Calcula o atraso atual, usando uma estratégia de backoff exponencial.
            # O atraso dobra a cada nova tentativa para evitar sobrecarregar a API.
            current_delay = NVD_API_DELAY * (2 ** retries)
            if retries > 0:
                logging.info(f"Tentando novamente consulta NVD para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}), atraso: {current_delay:.2f}s")
            
            time.sleep(current_delay) # Aguarda o tempo de atraso antes de fazer a requisição.

            # Faz a requisição GET para a API do NVD.
            # `timeout` define o tempo máximo de espera pela resposta.
            response = requests.get(nvd_api_url, timeout=15) # Aumentei o timeout para 15s.
            response.raise_for_status() # Levanta uma exceção HTTPError se a requisição retornar um status de erro (4xx ou 5xx).
            data = response.json() # Converte a resposta JSON em um dicionário Python.

            # 5. Processa a resposta da API do NVD
            if data and data.get('vulnerabilities'): # Verifica se a resposta contém dados de vulnerabilidades.
                vuln_data = data['vulnerabilities'][0]['cve'] # Pega os dados da primeira CVE encontrada (assumindo que a busca por ID retorna apenas uma).
                
                cvss_score = None # Inicializa a pontuação CVSS.
                if 'metrics' in vuln_data: # Verifica se existem métricas de CVSS na resposta.
                    # Tenta extrair a pontuação CVSS na ordem de preferência (V31, V30, V2).
                    if 'cvssMetricV31' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV31']:
                        cvss_score = vuln_data['metrics']['cvssMetricV31'][0]['cvssData'].get('baseScore')
                    elif 'cvssMetricV30' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV30']:
                        cvss_score = vuln_data['metrics']['cvssMetricV30'][0]['cvssData'].get('baseScore')
                    elif 'cvssMetricV2' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV2']:
                        cvss_score = vuln_data['metrics']['cvssMetricV2'][0]['cvssData'].get('baseScore')
            
                description = "Descrição não disponível." # Descrição padrão.
                if 'descriptions' in vuln_data: # Verifica se há descrições.
                    for desc in vuln_data['descriptions']: # Itera pelas descrições.
                        if desc['lang'] == 'en': # Busca a descrição em inglês.
                            description = desc['value']
                            break # Sai do loop assim que encontrar a descrição em inglês.
                
                severity_category = "low" # Severidade padrão antes de calcular.
                if cvss_score is not None: # Se a pontuação CVSS foi encontrada, determina a severidade.
                    if cvss_score >= 9.0:
                        severity_category = "critical"
                    elif cvss_score >= 7.0:
                        severity_category = "high"
                    elif cvss_score >= 4.0:
                        severity_category = "medium"
                    else:
                        severity_category = "low"
                else:
                    severity_category = "medium" # Padroniza para 'medium' se o CVSS não for encontrado no NVD.

                # 6. Constrói o resultado final com os detalhes da CVE.
                result = {
                    "severity": severity_category,
                    "cvss_score": cvss_score,
                    "summary": description,
                    "references": [ref['url'] for ref in vuln_data.get('references', []) if 'url' in ref] # Extrai URLs de referências.
                }
                cve_details_cache[cve_id] = result # Armazena os detalhes no cache em memória.
                return result, True # Retorna os detalhes e indica que foi buscado do NVD agora.

        # 7. Tratamento de Erros durante a consulta ao NVD
        except requests.exceptions.Timeout: # Captura erro de timeout na requisição.
            logging.error(f"Timeout ao consultar NVD para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
        except requests.exceptions.RequestException as req_err: # Captura erros gerais de requisição.
            if "429 Client Error" in str(req_err): # Verifica se o erro é devido a limite de taxa (429 Too Many Requests).
                logging.warning(f"Limite de requisições NVD atingido para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
            else:
                logging.error(f"Erro de requisição ao consultar NVD para {cve_id}: {req_err} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
        except (KeyError, IndexError) as ke: # Captura erros de estrutura de dados inesperada na resposta JSON.
            logging.warning(f"Estrutura inesperada na resposta do NVD para {cve_id} (KeyError/IndexError): {ke}")
            logging.debug(f"Resposta NVD para {cve_id}: {data}") # Loga a resposta completa para depuração.
        except Exception as e: # Captura qualquer outro erro genérico.
            logging.error(f"Erro genérico ao processar resposta do NVD para {cve_id}: {e}")
        
        retries += 1 # Incrementa o contador de tentativas.
    
    # 8. Retorno final em caso de falha em todas as tentativas
    logging.error(f"Todas as {MAX_NVD_RETRIES} tentativas de consulta ao NVD para {cve_id} falharam. Retornando detalhes padrão (Média).")
    cve_details_cache[cve_id] = default_cve_details # Cacheia o default para não tentar de novo na próxima vez.
    return default_cve_details, False # Retorna os detalhes padrão e indica que não foi buscado agora (falhou).

def run_scan(target, speed, port_option, os_detection):
    """
    Executa a varredura Nmap no alvo especificado com as opções fornecidas.
    Gera argumentos Nmap com base nos parâmetros de entrada, executa o scan e processa os resultados,
    incluindo a busca por detalhes de CVEs.
    """
    # 1. Pré-verificação: Nmap instalado
    if not is_nmap_installed():
        logging.error("Nmap não encontrado. Certifique-se de que está instalado e no PATH.")
        # Levanta um erro que será capturado pela rota da API, resultando em uma resposta 500.
        raise FileNotFoundError("Nmap não está instalado ou não está acessível no PATH do sistema.")

    nm = nmap.PortScanner() # Inicializa um objeto PortScanner da biblioteca python-nmap.
    arguments = [f"-{speed}"] # Lista para armazenar os argumentos do Nmap. `speed` (ex: 'T4') é o primeiro argumento.
    arguments.append("-sV") # Adiciona o argumento para detecção de versão de serviço, essencial para encontrar CVEs.
    logging.info("Detecção de versão de serviço (-sV) ativada.")

    # 2. Configuração de portas baseada na opção do usuário
    if port_option == "top_20":
        arguments.append("--top-ports 20")
        logging.info("Varredura nas 20 portas mais comuns ativada.")
    elif port_option == "top_100":
        arguments.append("--top-ports 100")
        logging.info("Varredura nas 100 portas mais comuns ativada.")
    elif port_option == "top_1000":
        arguments.append("--top-ports 1000")
        logging.info("Varredura nas 1000 portas mais comuns ativada.")
    elif port_option == "all_ports":
        arguments.append("-p-") # Varre todas as portas (1-65535).
        logging.info("Varredura em todas as portas ativada.")
    else:
        logging.warning(f"Opção de porta inválida: {port_option}. Usando padrão (top_1000).")
        arguments.append("--top-ports 1000") # Opção padrão se a entrada for inválida.

    # 3. Configuração de detecção de SO (Sistema Operacional)
    if os_detection: # Se a detecção de OS estiver ativada.
        arguments.append("-O") # Adiciona o argumento para detecção de OS.
        logging.info("Detecção de OS ativada. Isso pode exigir privilégios de root.")
    
    # 4. Adiciona o script 'vulners' para detecção de vulnerabilidades
    # O script 'vulners' do Nmap tenta identificar vulnerabilidades conhecidas em serviços.
    arguments.append("--script vulners")
    full_arguments = " ".join(arguments) # Combina todos os argumentos em uma única string.
    logging.info(f"Executando Nmap no target: {target} com argumentos: {full_arguments}")

    # 5. Execução do scan Nmap
    try:
        nm.scan(hosts=target, arguments=full_arguments) # Executa o comando Nmap.
    except nmap.PortScannerError as e: # Captura erros específicos da biblioteca python-nmap.
        logging.error(f"Erro do Nmap ao escanear {target}: {e}")
        raise ValueError(f"Erro ao executar o Nmap. Verifique o target ou as permissões: {e}") # Levanta um erro personalizado.
    except Exception as e: # Captura qualquer outro erro inesperado durante o scan.
        logging.error(f"Erro inesperado durante a varredura do Nmap em {target}: {e}")
        raise RuntimeError(f"Ocorreu um erro inesperado durante a varredura: {e}") # Levanta um erro de tempo de execução.

    results = [] # Lista para armazenar os resultados formatados do scan.
    if not nm.all_hosts(): # Verifica se o Nmap encontrou algum host ativo.
        logging.info(f"Nenhum host encontrado para o target: {target}")
        return results # Retorna uma lista vazia se nenhum host for encontrado.

    # NOVO: Não há mais limite de detalhes aqui. Todos serão buscados/cacheaddos.
    # A lógica de `nvd_details_fetched_count` e `MAX_NVD_DETAILS_FETCHED_PER_SCAN` foi removida.
    # `get_cve_severity_from_nvd` agora lida com as retentativas e cache.

    # 6. Processamento dos resultados do Nmap
    for host in nm.all_hosts(): # Itera sobre cada host encontrado pelo Nmap.
        services = [] # Lista para armazenar os serviços encontrados em cada host.
        os_details = { # Dicionário para armazenar detalhes do sistema operacional.
            "name": "Não detectado", "family": "Não detectado", "generation": "Não detectado", "accuracy": None, "cpe": []
        }
        
        # Detecção de Sistema Operacional (OS)
        if 'osmatch' in nm[host] and nm[host]['osmatch']: # Verifica se o Nmap encontrou correspondências de OS.
            first_osmatch = nm[host]['osmatch'][0] # Pega a primeira e mais provável correspondência.
            os_details["name"] = first_osmatch.get('name', 'Não detectado')
            os_class = first_osmatch.get('osclass', [{}])[0] # Pega a classe do OS.
            os_details["family"] = os_class.get('osfamily', 'Não detectado')
            os_details["generation"] = os_class.get('osgen', 'Não detectado')
            os_details["accuracy"] = first_osmatch.get('accuracy')
            os_details["cpe"] = os_class.get('cpe', []) # Common Platform Enumeration para o OS.
            logging.info(f"OS detectado para {host}: {os_details['name']}")
        elif 'os' in nm[host]: # Se 'osmatch' não foi encontrado, mas há dados 'os'.
            logging.info(f"Nmap encontrou dados de OS, mas sem 'osmatch' para {host}. Dados brutos: {nm[host]['os']}")
        else: # Nenhuma informação de OS.
            logging.info(f"Nenhuma informação de OS disponível para {host}.")

        # Detecção de Serviços e CVEs por porta
        for proto in nm[host].all_protocols(): # Itera sobre os protocolos (TCP, UDP, etc.).
            ports = nm[host][proto].keys() # Obtém as portas para o protocolo atual.
            for port in sorted(ports): # Itera sobre as portas, ordenadas numericamente.
                service = nm[host][proto][port] # Obtém os detalhes do serviço na porta/protocolo.
                # Extrai CVE IDs da saída bruta do script 'vulners' para este serviço.
                cve_ids_from_nmap_raw = extract_cves(service.get('script', {}).get('vulners', ''))
                # Remove CVEs duplicadas para o serviço atual.
                unique_cve_ids_for_service = list(set(cve_ids_from_nmap_raw))

                detailed_cves = [] # Lista para armazenar os detalhes completos das CVEs.
                for cve_id in unique_cve_ids_for_service:
                    # Chama get_cve_severity_from_nvd para obter detalhes da CVE.
                    # Esta função agora tem mais retentativas e padroniza para 'medium' em caso de falha.
                    cve_details, _ = get_cve_severity_from_nvd(cve_id) 
                    
                    # Adiciona os detalhes completos da CVE à lista `detailed_cves`.
                    detailed_cves.append({
                        "id": cve_id,
                        "severity": cve_details["severity"],
                        "cvss_score": cve_details["cvss_score"],
                        "summary": cve_details["summary"],
                        "references": cve_details["references"]
                    })
                    # O log agora reflete a severidade real ou a padronizada para 'medium'.
                    logging.info(f"CVE {cve_id} (Sev: {cve_details['severity']}, CVSS: {cve_details['cvss_score']}) encontrada para {host}:{port}")

                # Adiciona os detalhes do serviço (incluindo as CVEs detalhadas) à lista `services`.
                services.append({
                    "port": port, "protocol": proto, "name": service.get('name', 'unknown'),
                    "state": service.get('state', 'unknown'), "product": service.get('product', ''),
                    "version": service.get('version', ''), "extrainfo": service.get('extrainfo', ''),
                    "cpes": service.get('cpe', []), "cves": detailed_cves # As CVEs detalhadas são aninhadas aqui.
                })
        
        host_status = nm[host].state() # Obtém o status do host (ex: 'up' ou 'down').
        logging.info(f"Host {host} está {host_status}")

        # Adiciona os resultados completos do host à lista `results`.
        results.append({
            "ip": host, "hostname": nm[host].hostname(), "os_summary": os_details["name"],
            "os_details": os_details, "status": host_status, "services": services
        })

    save_cve_cache() # Salva o cache de CVEs em arquivo após a conclusão do scan.
    return results # Retorna a lista de resultados do scan.

# ---
## **Rotas da API**
# ---

@app.route('/scan', methods=['POST']) # Decorador que define a rota '/scan' que aceita requisições POST.
def scan():
    """
    Endpoint da API para iniciar uma varredura Nmap.
    Recebe os parâmetros do scan (target, speed, port_option, os_detection) via JSON na requisição POST.
    Retorna os resultados do scan ou uma mensagem de erro.
    """
    data = request.get_json() # Tenta extrair os dados JSON do corpo da requisição.
    if not data: # Verifica se os dados JSON foram recebidos.
        logging.warning("Requisição POST sem dados JSON.")
        return jsonify({"error": "Dados JSON inválidos na requisição."}), 400 # Retorna erro 400 (Bad Request).

    # Extrai os parâmetros do scan dos dados JSON.
    target = data.get('target')
    speed = data.get('speed')
    port_option = data.get('port_option')
    os_detection = data.get('os_detection', False) # `False` como valor padrão se 'os_detection' não estiver presente.

    # Validação de parâmetros obrigatórios
    if not target or not speed or not port_option:
        logging.warning(f"Campos obrigatórios faltando: target={target}, speed={speed}, port_option={port_option}")
        return jsonify({"error": "Campos 'target', 'speed' e 'port_option' são obrigatórios."}), 400

    logging.info(f"Recebida solicitação de scan para target: {target}, speed: {speed}, port_option: {port_option}, os_detection: {os_detection}")

    # 7. Execução do scan e tratamento de exceções
    try:
        results = run_scan(target, speed, port_option, os_detection) # Chama a função que executa o scan Nmap.
        if not results: # Se `run_scan` retornar uma lista vazia.
            return jsonify({"message": "Scan concluído, mas nenhum resultado encontrado para o target especificado. O host pode estar offline ou inacessível."}), 200
        return jsonify({"results": results}), 200 # Retorna os resultados do scan como JSON com status 200 (OK).
    except FileNotFoundError as e: # Captura o erro se o Nmap não estiver instalado.
        return jsonify({"error": str(e)}), 500 # Retorna erro 500 (Internal Server Error).
    except ValueError as e: # Captura erros relacionados a parâmetros inválidos ou problemas do Nmap.
        return jsonify({"error": str(e)}), 400 # Retorna erro 400 (Bad Request).
    except Exception as e: # Captura qualquer outra exceção inesperada.
        logging.exception("Erro inesperado durante a rota /scan:") # Registra a exceção completa no log.
        return jsonify({"error": f"Erro interno do servidor ao realizar a análise. Detalhes: {e}"}), 500 # Retorna erro 500.

# Bloco de execução principal
if __name__ == '__main__':
    """
    Este bloco é executado apenas quando o script é iniciado diretamente (não importado como módulo).
    É o ponto de entrada principal para a aplicação Flask.
    """
    load_cve_cache() # Carrega o cache de CVEs ao iniciar o servidor.
    if not is_nmap_installed(): # Verifica se o Nmap está instalado logo no início.
        logging.error("ATENÇÃO: Nmap não está instalado ou não está no PATH do sistema. A funcionalidade de scan não funcionará.")
    else:
        logging.info("Nmap detectado. O servidor está pronto para varreduras.")

    # Inicia o servidor Flask.
    # host='0.0.0.0' torna o servidor acessível de qualquer IP (útil em contêineres/VMs).
    # port=5000 define a porta onde o servidor irá escutar.
    # debug=True habilita o modo de depuração, que fornece recarregamento automático e depurador interativo.
    app.run(host='0.0.0.0', port=5000, debug=True)
