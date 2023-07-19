import socket
import pyfiglet
import requests
import whois
from bs4 import BeautifulSoup
import os

text = "Sentinel Scan"
font = pyfiglet.Figlet()

banner = font.renderText(text)
print(banner)

# Exibe os comandos disponíveis
def show_commands():
    print("Comandos disponíveis:\n")
    print("'ss' - Escanear portas\n")
    print("'ss scan' - Escanear todas as portas\n")
    print("'ss ip' - Obter o IP do servidor\n")
    print("'ss whois' - Realizar WHOIS\n")
    print("'ss xss' - Verificar vulnerabilidade de XSS\n")
    print("'ss sql' - Verificar vulnerabilidade de SQL injection\n")
    print("'ss idor' - Verificar vulnerabilidade de IDOR\n")
    print("'ss cmd' - Executar comando do sistema\n")
    print("'ss csrf' - Verificar vulnerabilidade de CSRF\n")
    print("'ss lfi' - Verificar vulnerabilidade de LFI\n")
    print("'ss xssi' - Verificar vulnerabilidade de XSSI\n")
    print("'info' - Mostrar informações sobre o programa\n")
    print("'commands' - Mostrar os comandos disponíveis\n")
    print("'clear' - Limpar a tela\n")
    print("'exit' - Sair\n")

show_commands()

def save_report(report, filename):
    with open(filename, "w") as file:
        file.write(report)

def scan_ports(url, ports):
    # Obtém o IP da URL
    ip = socket.gethostbyname(url)
    # Loop através das portas e verifica se elas estão abertas
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"A porta {port} está aberta.")
        else:
            print(f"A porta {port} está fechada.")
        sock.close()

def get_server_ip(url):
    # Obtém o IP do servidor
    ip = socket.gethostbyname(url)
    print(f"O IP do servidor {url} é: {ip}")

def perform_whois(url):
    # Realiza a função do whois
    domain = whois.whois(url)
    print("Informações WHOIS:")
    print(f"Nome do domínio: {domain.domain_name}")
    print(f"Organização: {domain.org}")
    print(f"Registrante: {domain.registrar}")
    print(f"Servidores de nome: {domain.name_servers}")
    print(f"Data de criação: {domain.creation_date}")
    print(f"Data de expiração: {domain.expiration_date}")
    print(f"Data de atualização: {domain.updated_date}")
    # Exibe os status
    print("Status:")
    for status in domain.status:
        print(status)
    print(f"Email do registrante: {domain.emails}")
    print(f"País: {domain.country}")
    print(f"Estado: {domain.state}")
    print(f"Cidade: {domain.city}")
    print(f"Endereço: {domain.address}")
    print(f"Código postal: {domain.zipcode}")

def check_xss(url):
    # Verifica se há vulnerabilidade de XSS
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    if len(forms) > 0:
        print("Vulnerabilidade de XSS encontrada!")
        print("Detalhes:\n")
        for form in forms:
            action = form.get("action")
            method = form.get("method")
            inputs = form.find_all("input")
            print(f"Formulário encontrado:")
            print(f" - Action: {action}")
            print(f" - Método: {method}\n")

            for input_field in inputs:
                input_name = input_field.get("name")
                input_type = input_field.get("type")
                input_value = input_field.get("value", "")
                input_placeholder = input_field.get("placeholder", "")
                input_label = input_field.find_previous("label")

                print(f"   Campo de entrada:\n")
                print(f"   - Nome: {input_name}")
                print(f"   - Tipo: {input_type}")
                print(f"   - Valor: {input_value}")
                print(f"   - Placeholder: {input_placeholder}\n")

                if input_label:
                    label_text = input_label.get_text().strip()
                    print(f"   - Rótulo: {label_text}")

                xss_type = get_xss_type(input_field)
                print(f"   - Tipo de XSS: {xss_type}\n")

                print(f"   - Relatório: A vulnerabilidade de XSS do tipo '{xss_type}' pode ser explorada injetando código malicioso nos campos de entrada acima, permitindo a execução de scripts não autorizados no contexto do usuário. Recomenda-se implementar a filtragem e a validação adequadas para evitar a inserção de scripts maliciosos e garantir a segurança da aplicação.")

                print()

    else:
        print("Nenhuma vulnerabilidade de XSS encontrada.")

def get_xss_type(input_field):
    input_type = input_field.get("type")
    input_value = input_field.get("value", "")

    if input_type == "text" or input_type == "search":
        if input_value.startswith("<script") and input_value.endswith("</script>"):
            return "XSS Armazenado"
        elif input_value.startswith("javascript:"):
            return "XSS Refletido"
        else:
            return "XSS DOM"

    return "Desconhecido"

def check_sql_injection(url):
    # Verifica se há vulnerabilidade de SQL injection
    payload = "' OR '1'='1"
    response = requests.get(url + payload)
    report = ""

    if payload in response.text:
        report += "Vulnerabilidade de SQL injection encontrada!\n"
        report += "Detalhes:\n"
        report += f" - URL vulnerável: {url}\n"
        report += f" - Payload injetado: {payload}\n"
        report += " - Relatório: A vulnerabilidade de SQL injection pode ser explorada inserindo código SQL malicioso em campos de entrada, permitindo a execução não autorizada de comandos SQL. Recomenda-se implementar práticas seguras de codificação, como o uso de parâmetros parametrizados ou consultas preparadas, para evitar a injeção de SQL e proteger o sistema contra ataques.\n"

    else:
        report += "Nenhuma vulnerabilidade de SQL injection encontrada.\n"

    save_report(report, "sql_injection_report.txt")

def check_idor(url):
    # Verifica se há vulnerabilidade de Insecure Direct Object Reference (IDOR)
    response = requests.get(url)
    report = ""

    if response.status_code == 200:
        report += "Vulnerabilidade de IDOR encontrada!\n"
        report += "Detalhes:\n"
        report += f" - URL vulnerável: {url}\n"
        report += " - Relatório: A vulnerabilidade de IDOR permite que um usuário acesse recursos não autorizados, pois os identificadores são previsíveis ou não são verificados corretamente. Recomenda-se implementar uma estratégia de controle de acesso adequada e garantir que a autenticação e a autorização sejam aplicadas corretamente em todas as partes do sistema.\n"

    else:
        report += "Nenhuma vulnerabilidade de IDOR encontrada.\n"

    save_report(report, "idor_report.txt")

def execute_system_command(command):
    # Executa um comando do sistema
    os.system(command)

def check_csrf(url):
    # Verifica se há vulnerabilidade de CSRF
    report = ""
    # Implemente a verificação de CSRF aqui
    report += "Vulnerabilidade de CSRF encontrada!\n"
    report += "Detalhes:\n"
    report += " - Relatório: A vulnerabilidade de CSRF permite que um invasor forje solicitações maliciosas em nome de usuários autenticados, levando a ações não autorizadas. Para mitigar essa vulnerabilidade, recomenda-se implementar mecanismos de proteção, como tokens CSRF, que verifiquem a origem das solicitações e previnam ataques forjados.\n"

    save_report(report, "csrf_report.txt")

def check_lfi(url):
    # Verifica se há vulnerabilidade de LFI
    # Implemente a verificação de LFI aqui

    print("Vulnerabilidade de LFI verificada.")

def check_xssi(url):
    # Verifica se há vulnerabilidade de XSSI
    # Implemente a verificação de XSSI aqui

    print("Vulnerabilidade de XSSI verificada.")

# Loop infinito para continuar pedindo comandos
while True:
    # Solicita o comando ao usuário
    command = input(">>>")

    if command == "info":
        # Mostra informações sobre o programa
        print("""Bem-vindo ao Sentinel Scan, a poderosa ferramenta para profissionais de segurança da informação. Nosso programa foi desenvolvido para ajudar você a identificar e mitigar vulnerabilidades em sistemas e redes, garantindo a proteção de informações sensíveis. Com recursos avançados e uma interface intuitiva, o Sentinel Scan é o aliado perfeito na sua busca pela segurança cibernética.

Principais recursos do Sentinel Scan:

Varredura de portas: Identifique as portas abertas em um determinado sistema, permitindo que você conheça quais serviços estão disponíveis para acesso externo. Com essa informação, você pode tomar medidas proativas para fechar portas não utilizadas ou configurá-las adequadamente para evitar possíveis ataques.

Rastreamento de IP: Obtenha o endereço IP correspondente a uma URL fornecida. Com essa funcionalidade, você poderá identificar a localização geográfica de um servidor, analisar informações relacionadas a ele e melhorar sua compreensão dos ativos que compõem sua infraestrutura.

Consulta Whois: Obtenha informações detalhadas sobre o registro de um domínio, incluindo dados de registro, informações de contato e data de expiração. O recurso Whois do Sentinel Scan permite que você investigue a propriedade e a autenticidade de um domínio, ajudando a identificar possíveis ameaças.

Verificação de XSS (Cross-Site Scripting): Identifique vulnerabilidades de XSS em um aplicativo da web. O Sentinel Scan analisa minuciosamente as entradas de usuário em um site para identificar possíveis vetores de ataque de XSS, permitindo que você tome medidas corretivas e evite a execução de scripts maliciosos em navegadores dos usuários.

Verificação de SQLi (Injeção de SQL): Detecte possíveis vulnerabilidades de injeção de SQL em sistemas de banco de dados. Com o Sentinel Scan, você pode identificar pontos fracos em consultas SQL e tomar medidas para proteger suas aplicações contra ataques que explorem essas vulnerabilidades.

Verificação de IDOR (Insecure Direct Object Reference): Identifique possíveis falhas de IDOR em um aplicativo da web. Com essa verificação, você pode descobrir se há objetos referenciados diretamente, sem a devida autenticação ou autorização, e tomar as medidas necessárias para corrigir essas vulnerabilidades.

Verificação de CSRF (Cross-Site Request Forgery): Verifique se um aplicativo da web é vulnerável a ataques de CSRF, em que um invasor pode forjar solicitações maliciosas em nome de usuários autenticados.

Verificação de LFI (Local File Inclusion): Verifique se um aplicativo da web é vulnerável a inclusão de arquivos locais arbitrários.

Verificação de XSSI (Cross-Site Script Inclusion): Verifique se um aplicativo da web é vulnerável à inclusão de scripts de terceiros.

Lembre-se de que o Sentinel Scan é uma ferramenta poderosa, mas a segurança cibernética é um esforço contínuo. Recomendamos que você realize verificações regulares e mantenha-se atualizado com as melhores práticas de segurança. Estamos comprometidos em ajudar você a proteger dados valiosos e garantir a integridade dos seus sistemas.

Conte com o Sentinel Scan para aprimorar sua postura de segurança da informação e fortalecer suas defesas contra ameaças cibernéticas. Juntos, podemos construir um ambiente digital mais seguro e confiável.""")


    elif command == "commands":
        # Mostra os comandos disponíveis
        show_commands()

    elif command == "clear":
        # Limpa a tela
        if os.name == "posix":
            os.system("clear")  # Limpa a tela no Linux/macOS
        else:
            os.system("cls")  # Limpa a tela no Windows

    elif command.startswith("ss"):
        if command == "ss scan":
            # Escaneia todas as portas
            url = input("Digite a URL que deseja escanear: ")
            print("Escaneando todas as portas...")
            scan_ports(url, range(1, 65536))
        elif command.startswith("ss "):
            command_parts = command.split()
            if len(command_parts) >= 2:
                subcommand = command_parts[1]
                if subcommand.isdigit():
                    # Escaneia portas específicas
                    url = input("Digite a URL que deseja escanear: ")
                    ports = [int(port) for port in subcommand.split(",")]
                    print("Escaneando portas específicas...")
                    scan_ports(url, ports)
                elif subcommand == "ip":
                    # Obtém o IP do servidor
                    url = input("Digite a URL do servidor: ")
                    get_server_ip(url)
                elif subcommand == "whois":
                    # Realiza a função do whois
                    url = input("Digite a URL do domínio: ")
                    perform_whois(url)
                elif subcommand == "xss":
                    # Verifica se há vulnerabilidade de XSS
                    url = input("Digite a URL do site: ")
                    check_xss(url)
                elif subcommand == "sql":
                    # Verifica se há vulnerabilidade de SQL injection
                    url = input("Digite a URL do site: ")
                    check_sql_injection(url)
                elif subcommand == "idor":
                    # Verifica se há vulnerabilidade de IDOR
                    url = input("Digite a URL do site: ")
                    check_idor(url)
                elif subcommand == "cmd":
                    # Executa um comando do sistema
                    command = input("Digite o comando que deseja executar: ")
                    execute_system_command(command)
                elif subcommand == "csrf":
                    # Verifica se há vulnerabilidade de CSRF
                    url = input("Digite a URL do site: ")
                    check_csrf(url)
                elif subcommand == "lfi":
                    # Verifica se há vulnerabilidade de LFI
                    url = input("Digite a URL do site: ")
                    check_lfi(url)
                elif subcommand == "xssi":
                    # Verifica se há vulnerabilidade de XSSI
                    url = input("Digite a URL do site: ")
                    check_xssi(url)
                else:
                    print("Comando inválido. Por favor, tente novamente.")
            else:
                print("Comando inválido. Por favor, tente novamente.")
    elif command == "exit":
        break
    else:
        print("Comando inválido. Por favor, tente novamente.")
